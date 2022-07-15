import * as Ed25519 from '@stablelib/ed25519';
import { Session } from './session';

type UserParams = {
  projectId: string | number;
  session: Session;
};

export class User {
  readonly #projectId: string | number;
  readonly #session: Session;

  constructor(params: UserParams) {
    if (!['string', 'number'].includes(typeof params.projectId)) {
      throw new TypeError('Expected \'projectId\' to be a string or a number');
    }

    if (!(params.session instanceof Session)) {
      throw new TypeError('Expected \'session\' to be a Session');
    }

    this.#projectId = params.projectId;
    this.#session = params.session;
  }

  get projectId() {
    return this.#projectId;
  }

  get issSigAlg() {
    return this.#session.issSigAlg;
  }

  get issSigKeyId() {
    return this.#session.issSigKeyId;
  }

  get subId() {
    return this.#session.subId;
  }

  get subSigAlg() {
    return this.#session.subSigAlg;
  }

  get subSigKeyId() {
    return this.#session.subSigKeyId;
  }

  /**
   * Sign a message using the session credentials.
   * @param {Uint8Array} data
   * @return {Uint8Array}
   */
  signMessage(data: Uint8Array): Uint8Array {
    return Ed25519.sign(this.#session.subSigPrivKey, data);
  }

  /**
   * Verify a message signature using the session credentials.
   * @note You should not use this directly since it is used to verify the identity provider server response.
   * @param {Uint8Array} data
   * @param {Uint8Array} signature
   * @return {boolean}
   */
  verifyMessage(data: Uint8Array, signature: Uint8Array): boolean {
    return Ed25519.verify(this.#session.issSigPubKey, data, signature);
  }
}