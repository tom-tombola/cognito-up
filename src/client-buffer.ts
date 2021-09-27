import { Buffer } from 'buffer/';

class ClientBuffer {
  public static toBuffer(data: string, encoding: string = 'utf-8'): Buffer {
    return typeof Buffer.from === 'function' && Buffer.from !== Uint8Array.from ? Buffer.from(data, encoding) : new Buffer(data, encoding);
  }

  public static alloc(size: number, fill?: string | Buffer | number, encoding: string = 'utf-8'): Buffer {
    if (typeof Buffer.alloc === 'function') {
      return Buffer.alloc(size, fill, encoding);
    } else {
      var buf = new Buffer(size);
      if (fill !== undefined && typeof buf.fill === 'function') {
        buf.fill(fill, undefined, undefined);
      }
      return buf;
    }
  }

  public static concat(buffers: Array<Buffer>): Buffer {
    var length = 0,
      offset = 0,
      buffer = null,
      i;

    for (i = 0; i < buffers.length; i++) {
      length += buffers[i].length;
    }

    buffer = ClientBuffer.alloc(length);

    for (i = 0; i < buffers.length; i++) {
      buffers[i].copy(buffer, offset);
      offset += buffers[i].length;
    }

    return buffer;
  }
}

export { Buffer, ClientBuffer };
