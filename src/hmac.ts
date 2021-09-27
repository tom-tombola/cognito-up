import { IHashFunction } from './hash';
import { bufferFromSecret, convertToBuffer, isEmptyData } from './helpers';
import { Digest } from './types';
import { Buffer } from './client-buffer';

export class Hmac {
  private hash: IHashFunction;
  private outer: IHashFunction;

  constructor(ctor: new () => IHashFunction, secret: any, blockSize: number) {
    this.hash = new ctor();
    this.outer = new ctor();

    const inner = bufferFromSecret(ctor, secret, blockSize);
    const outer = new Uint8Array(blockSize);
    outer.set(inner);

    for (let i = 0; i < blockSize; i++) {
      inner[i] ^= 0x36;
      outer[i] ^= 0x5c;
    }

    this.hash.update(inner);
    this.outer.update(outer);

    // Zero out the copied key buffer.
    for (let i = 0; i < inner.byteLength; i++) {
      inner[i] = 0;
    }
  }

  public update(val: Uint8Array) {
    if (isEmptyData(val)) {
      return this;
    }

    try {
      this.hash.update(convertToBuffer(val));
      return this;
    } catch (e) {
      return this;
    }
  }

  public digest(encoding: Digest) {
    if (!this.outer.finished) {
      this.outer.update(this.hash.digest() as Buffer);
    }

    return this.outer.digest(encoding);
  }
}
