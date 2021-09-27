import 'reflect-metadata';
import { Buffer, ClientBuffer } from './client-buffer';
import { ClientCrypto } from './client-crypto';

export const util = {
  Buffer,
  buffer: ClientBuffer,
  crypto: ClientCrypto,
};
