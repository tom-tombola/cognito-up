import { Algorithm, Digest } from './types';
import { ClientBuffer, Buffer } from './client-buffer';
import { util } from '.';
import { WordArray } from './word-array';
import { Hmac } from './hmac';
import { Sha256 } from './sha256';

export class ClientCrypto {
  public static createHmac(algorithm: Algorithm, key?: any): Hmac {
    if (algorithm === 'sha256') {
      return new Hmac(Sha256, key, Sha256.BLOCK_SIZE);
    }

    throw new Error('Unsupported hmac algorithm');
  }

  public static createHash(algorithm: Algorithm): any {
    if (algorithm === 'sha256') {
      return new Sha256();
    }

    throw new Error('Unsupported hash algorithm');
  }

  public static hmac(key: any, val: string | Buffer, digest?: Digest, algorithm?: Algorithm) {
    if (!digest) digest = 'binary';
    if (digest === 'buffer') {
      digest = undefined;
    }
    if (!algorithm) algorithm = 'sha256';
    if (typeof val === 'string') val = util.buffer.toBuffer(val);
    return ClientCrypto.createHmac(algorithm, key).update(val).digest(digest);
  }

  public static hash(algorithm: Algorithm, data: string | Buffer, digest: Digest = 'binary') {
    var hash = ClientCrypto.createHash(algorithm);
    if (digest === 'buffer') {
      digest = undefined;
    }
    if (typeof data === 'string') data = ClientBuffer.toBuffer(data);
    var isBuffer = Buffer.isBuffer(data);
    if (typeof ArrayBuffer !== 'undefined' && data && data.buffer instanceof ArrayBuffer) isBuffer = true;
    if (typeof data === 'object' && !isBuffer) {
      data = new util.Buffer(new Uint8Array(data));
    }
    return hash.update(data as Buffer).digest(digest);
  }

  public static randomBytes(size: number) {
    return Buffer.from(new WordArray().random(size).toString(), 'hex');
  }
}
