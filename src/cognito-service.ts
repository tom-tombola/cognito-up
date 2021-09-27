import {
  AttributeType,
  ChangePasswordCommand,
  CognitoIdentityProviderClient,
  CognitoIdentityProviderClientResolvedConfig,
  ConfirmForgotPasswordCommand,
  ConfirmSignUpCommand,
  ForgotPasswordCommand,
  GetUserAttributeVerificationCodeCommand,
  GetUserCommand,
  GetUserCommandInput,
  GetUserCommandOutput,
  GlobalSignOutCommand,
  InitiateAuthCommand,
  ResendConfirmationCodeCommand,
  RespondToAuthChallengeCommand,
  ServiceInputTypes,
  ServiceOutputTypes,
  SignUpCommand,
  UpdateUserAttributesCommand,
  VerifyUserAttributeCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import { Credentials } from 'aws-sdk';
import { Command } from '@aws-sdk/smithy-client';
import { AttributeData, getAttributesForTarget } from './decorators';
import { AwsSrp } from './srp';
import { IStorageAdapter, LocalStorageAdapter } from './storage';

export interface SignUpResult<T extends Record<string, any>> {
  confirmed: boolean;
  user: T;
}

export interface ICognitoService<T extends Record<string, any>> {
  readonly modelCtor: new () => T;

  signUp(user: T, password: string): Promise<SignUpResult<T>>;
  confirmSignUp(username: string, code: string): Promise<void>;
  resendConfirmCode(username: string): Promise<void>;
  signIn(username: string, password: string): Promise<void>;
  signOut(): Promise<void>;
  forgotPassword(username: string): Promise<void>;
  resetPassword(username: string, code: string, password: string): Promise<void>;
  changePassword(password: string, newPassword: string): Promise<void>;
  updateUser(user: T): Promise<void>;
  verifyEmail(code: string): Promise<void>;
  sendVerifyEmailCode(): Promise<void>;
  currentUser(bypassCache: boolean): Promise<T>;
  getToken(type: TokenType): string;
}

export enum TokenType {
  id = 'idToken',
  access = 'accessToken',
  refresh = 'refreshToken',
}

export interface ICognitoServiceConfig {
  clientId: string;
  userPoolId: string;
  region: string;
  storage?: IStorageAdapter;
}

export class CognitoService<T extends Record<string, any>> implements ICognitoService<T> {
  private readonly client: CognitoIdentityProviderClient;
  private readonly storage: IStorageAdapter;

  private readonly clientId: string;
  private readonly userPoolId: string;

  public readonly modelCtor: new () => T;

  constructor(config: ICognitoServiceConfig, modelCtor: new () => T) {
    const { clientId, userPoolId, region } = config;
    if (!clientId || !userPoolId || !region) {
      throw new Error('Invalid config object');
    }

    this.storage = config.storage ?? new LocalStorageAdapter();

    this.clientId = clientId;
    this.userPoolId = userPoolId;
    this.modelCtor = modelCtor;
    this.client = new CognitoIdentityProviderClient({
      region,
      credentials: new Credentials({ accessKeyId: '..', secretAccessKey: '..' }),
    });
  }

  public async currentUser(bypassCache: boolean = false): Promise<T> {
    const sessionUser = this.getFromStorage('app_session_user') as T;
    if (sessionUser && !bypassCache) {
      return sessionUser;
    }
    const accessToken = this.getTokenFromStorage(TokenType.access);
    if (!accessToken) {
      return null;
    }
    const input = new GetUserCommand({
      AccessToken: accessToken,
    });
    try {
      const response = await this.sendRequest<GetUserCommandInput, GetUserCommandOutput>(input);
      const user = this.attributesToUser(response.UserAttributes);

      this.setInStorage('app_session_user', user, 900000);
      return user;
    } catch (err) {
      // if access token expired send refresh token
      console.log(err);
      await this.refreshToken();
    }
  }

  public async signIn(username: string, password: string): Promise<void> {
    try {
      const srp = new AwsSrp(this.userPoolId.split('_')[1]);
      const A = srp.getLargeAValue();
      const command = new InitiateAuthCommand({
        ClientId: this.clientId,
        AuthFlow: 'USER_SRP_AUTH',
        AuthParameters: {
          USERNAME: username,
          SRP_A: A.toString(16),
        },
      });
      const response = await this.sendRequest(command);

      const challengeResponses = srp.getResponsesForChallenge(response.ChallengeParameters, password);
      const nextCommand = new RespondToAuthChallengeCommand({
        ClientId: this.clientId,
        ChallengeName: response.ChallengeName,
        ChallengeResponses: challengeResponses,
        Session: response.Session,
      });
      const nextResponse = await this.sendRequest(nextCommand);

      this.setTokenInStorage(TokenType.access, nextResponse.AuthenticationResult.AccessToken);
      this.setTokenInStorage(TokenType.refresh, nextResponse.AuthenticationResult.RefreshToken);
      this.setTokenInStorage(TokenType.id, nextResponse.AuthenticationResult.IdToken);
    } catch (err) {
      console.log(err);
      throw err;
    }
  }

  public async signOut(): Promise<void> {
    const command = new GlobalSignOutCommand({
      AccessToken: this.getTokenFromStorage(TokenType.access),
    });
    await this.sendRequest(command);
    this.setTokenInStorage(TokenType.access, null);
    this.setTokenInStorage(TokenType.refresh, null);
    this.setTokenInStorage(TokenType.id, null);
    this.setInStorage('app_session_user', null);
  }

  public async signUp(user: T, password: string): Promise<SignUpResult<T>> {
    const attributes: Record<string, AttributeData> = getAttributesForTarget(this.modelCtor.prototype);
    const UserAttributes = this.userToAttributes(user, attributes);
    const Username = user[attributes['username'].propertyName];

    const command = new SignUpCommand({
      ClientId: this.clientId,
      Password: password,
      Username,
      UserAttributes,
    });

    const response = await this.sendRequest(command);

    const k: keyof T = attributes['sub'].propertyName;
    user[k] = response.UserSub as T[keyof T];
    return {
      confirmed: response.UserConfirmed,
      user,
    };
  }

  public async confirmSignUp(username: string, code: string): Promise<void> {
    const command = new ConfirmSignUpCommand({
      ClientId: this.clientId,
      ConfirmationCode: code,
      ForceAliasCreation: true,
      Username: username,
    });
    await this.sendRequest(command);
  }

  public async resendConfirmCode(username: string): Promise<void> {
    const command = new ResendConfirmationCodeCommand({
      ClientId: this.clientId,
      Username: username,
    });
    await this.sendRequest(command);
  }

  public async forgotPassword(username: string): Promise<void> {
    const command = new ForgotPasswordCommand({
      ClientId: this.clientId,
      Username: username,
    });
    await this.sendRequest(command);
  }

  public async resetPassword(username: string, code: string, password: string): Promise<void> {
    const command = new ConfirmForgotPasswordCommand({
      ClientId: this.clientId,
      Username: username,
      Password: password,
      ConfirmationCode: code,
    });
    await this.sendRequest(command);
  }

  public async changePassword(password: string, newPassword: string): Promise<void> {
    try {
      const command = new ChangePasswordCommand({
        AccessToken: this.getTokenFromStorage(TokenType.access),
        PreviousPassword: password,
        ProposedPassword: newPassword,
      });
      await this.sendRequest(command);
    } catch (err) {
      console.log(err);
      throw err;
    }
  }

  public async updateUser(user: T): Promise<void> {
    try {
      const attributes: Record<string, AttributeData> = getAttributesForTarget(this.modelCtor.prototype);
      const UserAttributes = this.userToAttributes(user, attributes);
      const command = new UpdateUserAttributesCommand({
        AccessToken: this.getTokenFromStorage(TokenType.access),
        UserAttributes,
      });
      await this.sendRequest(command);
      await this.currentUser(true);
    } catch (err) {
      console.log(err);
      throw err;
    }
  }

  public async verifyEmail(code: string): Promise<void> {
    const command = new VerifyUserAttributeCommand({
      AccessToken: this.getTokenFromStorage(TokenType.access),
      AttributeName: 'email',
      Code: code,
    });
    await this.sendRequest(command);
    await this.currentUser(true);
  }

  public async sendVerifyEmailCode(): Promise<void> {
    try {
      const command = new GetUserAttributeVerificationCodeCommand({
        AccessToken: this.getTokenFromStorage(TokenType.access),
        AttributeName: 'email',
      });
      await this.sendRequest(command);
    } catch (err) {
      console.log(err);
      throw err;
    }
  }

  public getToken(type: TokenType): string {
    return this.getTokenFromStorage(type);
  }

  private attributesToUser(userAttributes: Array<AttributeType>) {
    const attributes: Record<string, AttributeData> = getAttributesForTarget(this.modelCtor.prototype);
    const user = new this.modelCtor();

    userAttributes
      .filter((attr) => attr.Name in attributes)
      .forEach((attr) => {
        user[attributes[attr.Name].propertyName as keyof T] = attr.Value as T[keyof T];
      });

    return user;
  }

  private userToAttributes(user: T, attributes: Record<string, AttributeData>): Array<AttributeType> {
    return Object.keys(attributes)
      .filter((k) => attributes[k].user && !attributes[k].readonly)
      .map((k) => ({ Name: k, Value: user[attributes[k].propertyName] }));
  }

  private getTokenFromStorage(type: TokenType) {
    return this.getFromStorage(type) as string;
  }

  private setTokenInStorage(type: TokenType, token: string) {
    this.setInStorage(type, token, -1);
  }

  private getFullKey(key: string) {
    return `${this.userPoolId}.${this.clientId}.${key}`;
  }

  private getFromStorage(key: string) {
    const fullKey = this.getFullKey(key);
    return this.storage.get(fullKey);
  }

  private setInStorage(key: string, item: any, ttl: number = 36000000) {
    const fullKey = this.getFullKey(key);
    if (item) {
      this.storage.set(fullKey, item, ttl);
    } else {
      this.storage.delete(fullKey);
    }
  }

  private async sendRequest<C extends ServiceInputTypes, O extends ServiceOutputTypes>(
    command: Command<C, O, CognitoIdentityProviderClientResolvedConfig>
  ): Promise<O> {
    try {
      return await this.client.send<C, O>(command);
    } catch (err: any) {
      console.log(err);
      if (err.message === 'Access Token has expired') {
        await this.refreshToken();
      } else {
        throw err;
      }
    }
  }

  private async refreshToken() {
    try {
      const command = new InitiateAuthCommand({
        ClientId: this.clientId,
        AuthFlow: 'REFRESH_TOKEN_AUTH',
        AuthParameters: {
          REFRESH_TOKEN: this.getTokenFromStorage(TokenType.refresh),
        },
      });
      const response = await this.sendRequest(command);

      this.setTokenInStorage(TokenType.access, response.AuthenticationResult.AccessToken);
      this.setTokenInStorage(TokenType.id, response.AuthenticationResult.IdToken);
    } catch (err) {
      console.log(err);
    }
  }
}
