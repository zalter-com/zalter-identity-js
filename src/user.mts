import * as Ed25519 from '@stablelib/ed25519';
import { Credential } from './credential.mjs';

type UserParams = {
  projectId: string | number;
  credential: Credential;
};

export class User {
  readonly #projectId: string | number;
  readonly #credential: Credential;

  constructor(params: UserParams) {
    if (!['string', 'number'].includes(typeof params.projectId)) {
      throw new TypeError('Expected "projectId" to be a string or a number');
    }

    if (!(params.credential instanceof Credential)) {
      throw new TypeError('Expected "credential" to be a Credential');
    }

    this.#projectId = params.projectId;
    this.#credential = params.credential;
  }

  get projectId() {
    return this.#projectId;
  }

  get issSigAlg() {
    return this.#credential.issSigAlg;
  }

  get issSigKeyId() {
    return this.#credential.issSigKeyId;
  }

  get subId() {
    return this.#credential.subId;
  }

  get subSigAlg() {
    return this.#credential.subSigAlg;
  }

  get subSigKeyId() {
    return this.#credential.subSigKeyId;
  }

  /**
   * Sign a message using the session credentials.
   * @param {Uint8Array} data
   * @return {Uint8Array}
   */
  signMessage(data: Uint8Array): Uint8Array {
    return Ed25519.sign(this.#credential.subSigPrivKey, data);
  }

  /**
   * Verify a message signature using the session credentials.
   * @note You should not use this directly since it is used to verify the identity provider server response.
   * @param {Uint8Array} data
   * @param {Uint8Array} signature
   * @return {boolean}
   */
  verifyMessage(data: Uint8Array, signature: Uint8Array): boolean {
    return Ed25519.verify(this.#credential.issSigPubKey, data, signature);
  }
}