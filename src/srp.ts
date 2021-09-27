import { util } from '.';
import { Buffer } from './client-buffer';
import { BigInteger } from 'jsbn';

const initN =
  'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' +
  '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' +
  'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' +
  'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
  'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' +
  'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' +
  '83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
  '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
  'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' +
  'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' +
  '15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64' +
  'ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7' +
  'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B' +
  'F12FFA06D98A0864D87602733EC86A64521F2B18177B200C' +
  'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31' +
  '43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF';

export class AwsSrp {
  private N: BigInteger;
  private g: BigInteger;
  private k: BigInteger;
  private smallAValue: BigInteger;
  private largeAValue: BigInteger;
  private UValue: BigInteger;
  private UHexHash: string;
  private infoBits;
  private poolName: string;

  constructor(poolName: string) {
    this.N = new BigInteger(initN, 16);
    this.g = new BigInteger('2', 16);
    this.k = new BigInteger(this.hexHash(`00${this.N.toString(16)}0${this.g.toString(16)}`), 16);

    this.smallAValue = this.generateRandomSmallA();
    this.getLargeAValue();

    this.infoBits = new util.Buffer('Caldera Derived Key', 'utf8');

    this.poolName = poolName;
  }

  public getLargeAValue(): BigInteger {
    if (this.largeAValue) {
      return this.largeAValue;
    } else {
      const largeAValue = this.calculateA(this.smallAValue);
      this.largeAValue = largeAValue;
      return this.largeAValue;
    }
  }

  public getResponsesForChallenge(challengeParameters: any, password: string) {
    const serverBValue = new BigInteger(challengeParameters.SRP_B, 16);
    const salt = new BigInteger(challengeParameters.SALT, 16);
    const usernameForSrp = challengeParameters.USER_ID_FOR_SRP;
    const hkdf = this.getPasswordAuthenticationKey(usernameForSrp, password, serverBValue, salt);
    const now = this.getUTCNow();
    const signatureString = util.crypto.hmac(
      hkdf,
      util.buffer.concat([
        new util.Buffer(this.poolName, 'utf8'),
        new util.Buffer(usernameForSrp, 'utf8'),
        new util.Buffer(challengeParameters.SECRET_BLOCK, 'base64'),
        new util.Buffer(now, 'utf8'),
      ]),
      'base64',
      'sha256'
    );

    return {
      USERNAME: usernameForSrp,
      PASSWORD_CLAIM_SECRET_BLOCK: challengeParameters.SECRET_BLOCK,
      TIMESTAMP: now,
      PASSWORD_CLAIM_SIGNATURE: signatureString as string,
    };
  }

  private getSmallAValue(): BigInteger {
    return this.smallAValue;
  }

  public getPasswordAuthenticationKey(username: string, password: string, serverBValue: BigInteger, salt: BigInteger): string {
    if (serverBValue.mod(this.N).equals(BigInteger.ZERO)) {
      throw new Error('B cannot be zero.');
    }

    this.UValue = this.calculateU(this.largeAValue, serverBValue);

    if (this.UValue.equals(BigInteger.ZERO)) {
      throw new Error('U cannot be zero.');
    }

    const usernamePassword = `${this.poolName}${username}:${password}`;
    const usernamePasswordHash = this.hash(usernamePassword);

    const xValue = new BigInteger(this.hexHash(this.padHex(salt) + usernamePasswordHash), 16);
    const sValue = this.calculateS(xValue, serverBValue);
    return this.computehkdf(new util.Buffer(this.padHex(sValue), 'hex'), new util.Buffer(this.padHex(this.UValue.toString(16)), 'hex')) as string;
  }

  private generateRandomSmallA(): BigInteger {
    const hexRandom = util.crypto.randomBytes(128).toString('hex');

    const randomBigInt = new BigInteger(hexRandom, 16);
    const smallABigInt = randomBigInt.mod(this.N);

    return smallABigInt;
  }

  private calculateA(a: BigInteger): BigInteger {
    const A = this.g.modPow(a, this.N);

    if (A.mod(this.N).equals(BigInteger.ZERO)) {
      throw new Error('Illegal paramater. A mod N cannot be 0.');
    }

    return A;
  }

  private calculateU(A: BigInteger, B: BigInteger): BigInteger {
    this.UHexHash = this.hexHash(this.padHex(A) + this.padHex(B));
    const finalU = new BigInteger(this.UHexHash, 16);

    return finalU;
  }

  private hash(buf: string | Buffer): string {
    const hashHex = util.crypto.hash('sha256', buf, 'hex');
    return new Array(64 - hashHex.length).join('0') + hashHex;
  }

  private hexHash(hexStr: string): string {
    return this.hash(new util.Buffer(hexStr, 'hex'));
  }

  private computehkdf(ikm: Buffer, salt: Buffer) {
    const prk = util.crypto.hmac(salt, ikm, 'buffer', 'sha256');
    const infoBitsUpdate = util.buffer.concat([this.infoBits, new util.Buffer(String.fromCharCode(1), 'utf8')]);
    const hmac = util.crypto.hmac(prk, infoBitsUpdate, 'buffer', 'sha256');
    return hmac.slice(0, 16);
  }

  private calculateS(xValue: BigInteger, serverBValue: BigInteger): BigInteger {
    const gModPowXN = this.g.modPow(xValue, this.N);

    const intValue2 = serverBValue.subtract(this.k.multiply(gModPowXN));
    const result = intValue2.modPow(this.smallAValue.add(this.UValue.multiply(xValue)), this.N);

    return result.mod(this.N);
  }

  private padHex(bigInt: string | BigInteger): string {
    let hashStr = bigInt.toString(16);
    if (hashStr.length % 2 === 1) {
      hashStr = `0${hashStr}`;
    } else if ('89ABCDEFabcdef'.indexOf(hashStr[0]) !== -1) {
      hashStr = `00${hashStr}`;
    }
    return hashStr;
  }

  public getUTCNow() {
    const now = new Date();
    const weekDay = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'][now.getUTCDay()];
    var month = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'][now.getUTCMonth()];
    var day = now.getUTCDate();

    const hours = now.getUTCHours();
    let hourStr = hours.toString();
    if (hours < 10) {
      hourStr = '0' + hours;
    }

    const minutes = now.getUTCMinutes();
    let minutesStr = hours.toString();
    if (minutes < 10) {
      minutesStr = '0' + minutes;
    }

    const seconds = now.getUTCSeconds();
    let secondsStr = hours.toString();
    if (seconds < 10) {
      secondsStr = '0' + seconds;
    }

    const year = now.getUTCFullYear();

    // ddd MMM D HH:mm:ss UTC YYYY
    return weekDay + ' ' + month + ' ' + day + ' ' + hourStr + ':' + minutesStr + ':' + secondsStr + ' UTC ' + year;
  }
}
