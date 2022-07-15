type SessionParams = {
  issSigAlg: string;
  issSigKeyId: string | number;
  issSigPubKey: Uint8Array;
  subId: string | number;
  subSigAlg: string;
  subSigKeyId: string | number;
  subSigPrivKey: Uint8Array;
  projectId: string | number;
  expiresAt: string | number;
};

export class Session {
  readonly issSigAlg: string;
  readonly issSigKeyId: string | number;
  readonly issSigPubKey: Uint8Array;
  readonly subId: string | number;
  readonly subSigAlg: string;
  readonly subSigKeyId: string | number;
  readonly subSigPrivKey: Uint8Array;
  readonly projectId: string | number;
  readonly expiresAt: string | number;

  /**
   * @param {Object} params
   */
  constructor(params: SessionParams) {
    if (typeof params.issSigAlg !== 'string') {
      throw new TypeError('Expected \'issSigAlg\' to be a string');
    }

    if (!['string', 'number'].includes(typeof params.issSigKeyId)) {
      throw new TypeError('Expected \'issSigKeyId\' to be a string');
    }

    if (!(params.issSigPubKey instanceof Uint8Array)) {
      throw new TypeError('Expected \'issSigPubKey\' to be an Uint8Array');
    }

    if (!['string', 'number'].includes(typeof params.subId)) {
      throw new TypeError('Expected \'subId\' to be a string or a number');
    }

    if (typeof params.subSigAlg !== 'string') {
      throw new TypeError('Expected \'subSigAlg\' to be a string');
    }

    if (!['string', 'number'].includes(typeof params.subSigKeyId)) {
      throw new TypeError('Expected \'subSigKeyId\' to be a string');
    }

    if (!(params.subSigPrivKey instanceof Uint8Array)) {
      throw new TypeError('Expected \'subSigPrivKey\' to be an Uint8Array');
    }

    if (!['string', 'number'].includes(typeof params.projectId)) {
      throw new TypeError('Expected \'projectId\' to be a string or a number');
    }

    if (!['string', 'number'].includes(typeof params.expiresAt)) {
      throw new TypeError('Expected \'expiresAt\' to be a string or a number');
    }

    this.issSigAlg = params.issSigAlg;
    this.issSigKeyId = params.issSigKeyId;
    this.issSigPubKey = params.issSigPubKey;
    this.subId = params.subId;
    this.subSigAlg = params.subSigAlg;
    this.subSigKeyId = params.subSigKeyId;
    this.subSigPrivKey = params.subSigPrivKey;
    this.projectId = params.projectId;
    this.expiresAt = params.expiresAt;
  }
}