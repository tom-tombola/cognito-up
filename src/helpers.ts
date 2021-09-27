import { Buffer } from './client-buffer';
// import { IHash } from './hash';

export const bufferFromSecret = (ctor: new () => any, secret: any, blockSize: number) => {
  var input = convertToBuffer(secret);
  if (input.byteLength > blockSize) {
    const bufferHash = new ctor();
    bufferHash.update(input);
    input = bufferHash.digest() as Uint8Array;
  }
  var buffer = new Uint8Array(blockSize);
  buffer.set(input);
  return buffer;
};

export const isEmptyData = (data: any): boolean => {
  if (typeof data === 'string') {
    return data.length === 0;
  }
  return data.byteLength === 0;
};

export const convertToBuffer = (data: any) => {
  if (typeof data === 'string') {
    data = new Buffer(data, 'utf8');
  }

  if (ArrayBuffer.isView(data)) {
    const { buffer, byteOffset, byteLength } = data as ArrayBufferView;
    return new Uint8Array(buffer, byteOffset, byteLength / Uint8Array.BYTES_PER_ELEMENT);
  }

  return new Uint8Array(data);
};
