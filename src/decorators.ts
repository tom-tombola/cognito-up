const ATTR_KEY = Symbol('cognito:attribute');
export interface AttributeData {
  propertyName: string;
  user: boolean;
  readonly: boolean;
}

export const getAttributesForTarget = (target: any): Record<string, AttributeData> | undefined => {
  const attributes = Reflect.getMetadata(ATTR_KEY, target);
  if (attributes) {
    return Object.keys(attributes).reduce((obj: Record<string, AttributeData>, key: string) => {
      obj[key] = attributes[key];
      return obj;
    }, {});
  }
};

const setAttributeMetadata = (target: any, attributes: Record<string, AttributeData>): void => {
  Reflect.defineMetadata(ATTR_KEY, attributes, target);
};

const addAttributeForTarget = (target: any, propertyName: string, name: string, user: boolean, readonly: boolean): void => {
  let attributes = getAttributesForTarget(target);
  if (!attributes) {
    attributes = {};
  }

  attributes[name] = { propertyName, user, readonly };
  setAttributeMetadata(target, attributes);
};

const cognitoAttribute = (name: string, user: boolean, readonly: boolean = false) => {
  return (target: any, propertyName: string) => {
    addAttributeForTarget(target, propertyName, name, user, readonly);
  };
};

export const Username = () => cognitoAttribute('username', false);
export const Sub = () => cognitoAttribute('sub', false);

export const Email = () => cognitoAttribute('email', true);
export const GivenName = () => cognitoAttribute('given_name', true);
export const EmailVerified = () => cognitoAttribute('email_verified', true, true);
export const Custom = (name: string) => cognitoAttribute(`custom:${name}`, true);
