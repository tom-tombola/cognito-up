import { Buffer } from './client-buffer';
import { Digest } from './types';

export interface IHashFunction {
  finished: boolean;
  update(val: Uint8Array): IHashFunction;
  digest(encoding?: Digest): Buffer | string;
}
