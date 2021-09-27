export interface IStorageAdapter {
  set(key: string, item: any, ttl: number): void;
  get(key: string): any;
  delete(key: string): void;
}

export class LocalStorageAdapter implements IStorageAdapter {
  public set(key: string, value: any, ttl: number = 36000000): void {
    const now = new Date();
    const item = {
      value,
      expiry: ttl >= 0 ? now.getTime() + ttl : null,
    };
    localStorage.setItem(key, JSON.stringify(item));
  }

  public get(key: string): any {
    const itemStr = localStorage.getItem(key);
    if (!itemStr) {
      return null;
    }

    const item = JSON.parse(itemStr);
    if (item.expiry) {
      const now = new Date();
      if (now.getTime() > item.expiry) {
        localStorage.removeItem(key);
        return null;
      }
    }

    return item.value;
  }

  public delete(key: string): void {
    localStorage.removeItem(key);
  }
}
