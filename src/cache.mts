export abstract class Cache {
  /** Returns the store size */
  abstract get length(): Promise<number>;

  /** Clear the store */
  abstract clear(): Promise<void>;

  /** Get an item from the store */
  abstract getItem(key: string): Promise<string | null>;

  /** Remove an item from the store */
  abstract removeItem(key: string): Promise<void>;

  /** Set an item in the store */
  abstract setItem(key: string, value: string): Promise<void>;
}

class LocalStorageCache implements Cache {
  #store = globalThis.localStorage;

  get length(): Promise<number> {
    return Promise.resolve(this.#store.length);
  }

  clear(): Promise<void> {
    this.#store.clear();
    return Promise.resolve();
  }

  getItem(key: string): Promise<string | null> {
    return Promise.resolve(this.#store.getItem(key));
  }

  removeItem(key): Promise<void> {
    this.#store.removeItem(key);
    return Promise.resolve();
  }

  setItem(key, value): Promise<void> {
    this.#store.setItem(key, value);
    return Promise.resolve();
  }
}

class MemoryCache implements Cache {
  #store = new Map();

  get length(): Promise<number> {
    return Promise.resolve(this.#store.size);
  }

  clear(): Promise<void> {
    this.#store.clear();
    return Promise.resolve();
  }

  getItem(key: string): Promise<string | null> {
    return Promise.resolve(this.#store.get(key));
  }

  removeItem(key): Promise<void> {
    this.#store.delete(key);
    return Promise.resolve();
  }

  setItem(key, value): Promise<void> {
    this.#store.set(key, value);
    return Promise.resolve();
  }
}

export function getCache(): Cache {
  const testKey = 'zalter.storage-test';
  const testValue = 'i\'m a teapot';

  try {
    globalThis.localStorage.setItem(testKey, testValue);

    if (globalThis.localStorage.getItem(testKey) !== testValue) {
      throw new Error('Invalid LocalStorage behaviour.');
    }

    return new LocalStorageCache();
  } catch {
    return new MemoryCache();
  } finally {
    try {
      globalThis.localStorage.removeItem(testKey);
    } catch {}
  }
}