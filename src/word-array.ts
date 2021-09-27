export class WordArray {
  public words: Array<number>;
  public sigBytes;

  constructor(words?: Array<number>, sigBytes?: number) {
    words = this.words = words || [];

    if (sigBytes) {
      this.sigBytes = sigBytes;
    } else {
      this.sigBytes = words.length * 4;
    }
  }

  public random(size: number) {
    const words: Array<number> = [];

    for (let i = 0; i < size; i += 4) {
      words.push(this.cryptoSecureRandomInt());
    }

    return new WordArray(words, size);
  }

  public toString() {
    const { words, sigBytes } = this;
    const hexChars: Array<string> = [];
    for (let i = 0; i < sigBytes; i++) {
      const bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
      hexChars.push((bite >>> 4).toString(16));
      hexChars.push((bite & 0x0f).toString(16));
    }

    return hexChars.join('');
  }

  private cryptoSecureRandomInt(): number {
    if (crypto) {
      try {
        return crypto.getRandomValues(new Uint32Array(1))[0];
      } catch (err) {}
    }

    throw new Error('Native crypto module could not be used to get secure random number.');
  }
}
