export class Random {
  /**
   * Generate random Uint8Array
   * @param {number} length
   * @return {Uint8Array}
   */
  static uint8Array(length: number): Uint8Array {
    const vector = globalThis.crypto.getRandomValues(new Uint8Array(length));
    const xorb = Math.floor(Math.random() * 1e12) % 256;

    for (let i = 0; i < vector.length; i++) {
      vector[i] ^= xorb;
    }

    return vector;
  }
}