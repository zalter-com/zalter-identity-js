import * as CBOR from '@stablelib/cbor';
import * as Ed25519 from '@stablelib/ed25519';
import * as X25519 from '@stablelib/x25519';
import * as XSalsa20 from '@stablelib/xsalsa20';
import { XChaCha20Poly1305 } from '@stablelib/xchacha20poly1305';
import { Scrypt } from '@stablelib/scrypt';
import { default as Base64Url } from 'base64url';
import { Buffer } from 'buffer';
import { EventEmitter } from './event-emitter.mjs';
import { ApiClient } from './api-client.mjs';
import { BASE_ENDPOINT } from './constants.mjs';
import { Credential } from './credential.mjs';
import { ContentType, HttpHeader, HttpMethod } from './http.mjs';
import { createServiceException } from './exception.mjs';
import { Logger } from './logger.mjs';
import { Cache, getCache } from './cache.mjs';
import { TimeDrifter } from './time-drifter.mjs';
import { User } from './user.mjs';
import { assert } from './utils/assert.mjs';
import { concatUint8Arrays } from './utils/concat-uint8arrays.mjs';
import { Random } from './utils/random.mjs';

const EMPTY_BUFFER = Buffer.alloc(0);

const scrypt = new Scrypt(4096, 4, 1);

const logger = new Logger('Auth');

enum Endpoint {
  START_CODE_SIGN_IN = '/v1/auth/signIn/code:start',
  CONTINUE_CODE_SIGN_IN = '/v1/auth/signIn/code:continue',
  FINALIZE_CODE_SIGN_IN = '/v1/auth/signIn/code:finalize',

  START_LINK_SIGN_IN = '/v1/auth/signIn/link:start',
  FINALIZE_LINK_SIGN_IN = '/v1/auth/signIn/link:finalize',

  VERIFY_MFA_CHALLENGE = '/v1beta/auth/factors/challenge:verify',

  SIGN_OUT = '/v1/account/sessions:deleteCurrent'
}

interface State {
  sessionId: string;
  // Used to encrypt sign-in session data
  sharedKey?: Uint8Array;
  // Issuer challenge for code sign-in process
  issChallenge?: Uint8Array;
  // Issuer signing public key for code sign-in process
  issSigPubKey?: Uint8Array;
  // Subject signing private key
  subSigPrivKey?: Uint8Array;
}

type CodeFlow = 'start' | 'finalize';

type LinkFlow = 'start' | 'finalize';

enum CoseAlgorithm {
  xChaCha20Poly1305 = 24,
  XSalsa20 = 'x:520' // custom
}

enum CoseHeader {
  alg = 1,
  IV = 5
}

type CoseProtectedHeaders = ArrayBufferLike;

type CoseUnprotectedHeaders = Record<CoseHeader, any> & {
  1?: CoseAlgorithm;
  5?: Uint8Array;
}

type CoseCiphertext = Uint8Array | null;

type CoseEncryption = [CoseProtectedHeaders, CoseUnprotectedHeaders, CoseCiphertext];

type Factor = {
  id: string;
  type: string;
  provider: string;
};

type AuthDetails = {
  expiresAt: string;
  issSigAlg: string;
  issSigKeyId: string;
  issSigPubKey: Uint8Array;
  subId: string;
  subSigAlg: string;
  subSigKeyId: string;
};

interface CodeStartParams {
  email?: string;
  phoneNumber?: string;
}

interface CodeFinalizeParams {
  code: string;
}

interface LinkStartParams {
  email: string;
  redirectUri: string;
}

interface LinkFinalizeParams {
  token: string;
}

interface VerifyMfaChallengeParams {
  factorId: string;
  code: string;
}

interface AuthenticateParams {
  issSigAlg: string;
  issSigKeyId: string;
  issSigPubKey: Uint8Array;
  subId: string;
  subSigAlg: string;
  subSigKeyId: string;
  subSigPrivKey: Uint8Array;
  projectId: string;
  expiresAt: string;
}

interface AuthConfig {
  projectId: string;
  endpoint?: {
    authority: string;
    scheme: 'http' | 'https';
  };
}

/**
 * A client for the Zalter Identity Service API.
 */
export class Auth {
  readonly emitter = new EventEmitter();
  readonly #projectId: string;
  readonly #apiClient: ApiClient;
  readonly #cache: Cache;

  /** In memory cached user for quick access */
  #user: User | null = null;

  /** Internal state during authentication process */
  #state: State | null = null;

  /**
   * @param {AuthConfig} config
   */
  constructor(config: AuthConfig) {
    if (!config) {
      throw new Error('Configuration is required.');
    }

    if (!config.projectId) {
      throw new Error('Project ID is required.');
    }

    this.#projectId = config.projectId;

    // Setup cache storage
    this.#cache = getCache();

    // Setup API Client
    this.#apiClient = new ApiClient({
      endpoint: config.endpoint || BASE_ENDPOINT,
      timeDrifter: new TimeDrifter(),
      auth: this
    });
  }

  /**
   * Return the authentication state.
   * @return {Promise<boolean>}
   */
  async isAuthenticated(): Promise<boolean> {
    return !!await this.getCurrentUser();
  }

  /**
   * Get the authenticated user.
   * @return {Promise<any>}
   */
  async getCurrentUser(): Promise<User | null> {
    if (this.#user) {
      return this.#user;
    }

    const cachePrefix = `zalter.auth.${this.#projectId}`;

    const currentUserCacheKey = `${cachePrefix}.currentUser`;
    const currentUserId = await this.#cache.getItem(currentUserCacheKey);

    if (!currentUserId) {
      return null;
    }

    let user = null;

    const userCacheKey = `${cachePrefix}.users.${currentUserId}`;
    const rawData = await this.#cache.getItem(userCacheKey);

    if (rawData) {
      try {
        const data = CBOR.decode(Buffer.from(rawData, 'base64'));

        // TODO: Check if credential expired

        const credential = new Credential({
          issSigAlg: data.issSigAlg,
          issSigKeyId: data.issSigKeyId,
          issSigPubKey: data.issSigPubKey,
          subId: data.subId,
          subSigAlg: data.subSigAlg,
          subSigKeyId: data.subSigKeyId,
          subSigPrivKey: data.subSigPrivKey,
          projectId: data.projectId,
          expiresAt: data.expiresAt
        });

        user = new User({
          projectId: data.projectId,
          credential
        });
      } catch (err) {
        logger.error('Unable to decode the credential, removing it from cache.', err);
        this.#cache.removeItem(userCacheKey).catch(logger.error);
        this.#cache.removeItem(currentUserCacheKey).catch(logger.error);
      }
    }

    this.#user = user;
    return this.#user;
  }

  /**
   * Sign in with a code.
   * @param {"start" | "finalize"} flow
   * @param {unknown} params
   * @return {Promise<void>}
   */
  signInWithCode(flow: CodeFlow, params: CodeStartParams | CodeFinalizeParams): Promise<any> {
    switch (flow) {
      case 'start':
        return this.#signInCodeStart(params as CodeStartParams);
      case 'finalize':
        return this.#signInCodeContinue(params as CodeFinalizeParams);
      default:
        throw new Error('Invalid flow');
    }
  }

  /**
   * Sign in with a link.
   * @param {"start" | "finalize"} flow
   * @param {unknown} params
   * @return {Promise<void>}
   */
  signInWithLink(flow: LinkFlow, params: LinkStartParams | LinkFinalizeParams): Promise<any> {
    switch (flow) {
      case 'start':
        return this.#signInLinkStart(params as LinkStartParams);
      case 'finalize':
        return this.#signInLinkFinalize(params as LinkFinalizeParams);
      default:
        throw new Error('Invalid flow');
    }
  }

  /**
   * Verify MFA challenge.
   * @param {Object} params
   * @return {Promise<any>}
   */
  verifyMfaChallenge(params: VerifyMfaChallengeParams): Promise<any> {
    assert(this.#state?.sharedKey, 'Must finish primary authentication');
    assert(params.factorId, 'Authenticator ID is required');
    assert(params.code, 'Code is required');

    const xChaCha20Poly1305 = new XChaCha20Poly1305(this.#state.sharedKey);

    // Data to encrypt
    const data = {
      factorId: params.factorId,
      code: params.code
    };

    // Encrypt data
    const nonce = Random.uint8Array(24);
    const ciphertext = xChaCha20Poly1305.seal(nonce, CBOR.encode(data));
    const encrypted = CBOR.encode([
      EMPTY_BUFFER,
      {
        [CoseHeader.alg]: CoseAlgorithm.xChaCha20Poly1305,
        [CoseHeader.IV]: nonce
      },
      ciphertext
    ] as CoseEncryption);

    return this.#apiClient
      .request({
        path: Endpoint.VERIFY_MFA_CHALLENGE,
        method: HttpMethod.POST,
        headers: {
          [HttpHeader.CONTENT_TYPE]: ContentType.APPLICATION_CBOR
        },
        body: CBOR.encode({
          sessionId: this.#state.sessionId,
          encrypted
        })
      })
      .then(async (response) => {
        if (response.status >= 300) {
          return createServiceException(response);
        }

        const payload = CBOR.decode(new Uint8Array(await response.arrayBuffer()));

        if (payload.status === 'AUTHENTICATED') {
          const encrypted: CoseEncryption = CBOR.decode(payload.encrypted);

          // Decrypt and decode authDetails
          const { authDetails } = CBOR.decode(xChaCha20Poly1305.open(
            encrypted[1][CoseHeader.IV],
            encrypted[2]
          )) as { authDetails: AuthDetails };

          // Cleanup internal state
          const subSigPrivKey = this.#state.subSigPrivKey;
          this.#state = null;

          await this.#authenticate({
            issSigAlg: authDetails.issSigAlg,
            issSigKeyId: authDetails.issSigKeyId,
            issSigPubKey: authDetails.issSigPubKey,
            subId: authDetails.subId,
            subSigAlg: authDetails.subSigAlg,
            subSigKeyId: authDetails.subSigKeyId,
            subSigPrivKey,
            projectId: this.#projectId,
            expiresAt: authDetails.expiresAt
          });

          return {
            status: 'AUTHENTICATED'
          };
        }

        throw new Error('Status handler not implemented');
      });
  }

  /**
   * Sign out.
   * @param {boolean} [globalSignOut = true] - Sign out from server
   * @return {Promise<void>}
   */
  async signOut(globalSignOut: boolean = true): Promise<void> {
    const user = await this.getCurrentUser();

    if (!user) {
      logger.error('Unable to sign out, user not signed in.');
      return;
    }

    if (globalSignOut) {
      try {
        const response = await this.#apiClient.request({
          path: Endpoint.SIGN_OUT,
          method: HttpMethod.POST,
          options: {
            signRequest: true,
            verifyResponse: true
          }
        });

        if (response.status >= 300) {
          await createServiceException(response);
          return;
        }
      } catch (err) {
        logger.error('Unable to sign out from server.', err);
        // TODO: Maybe throw here to let the user know
      }
    }

    try {
      const cachePrefix = `zalter.auth.${this.#projectId}`;
      await this.#cache.removeItem(`${cachePrefix}.currentUser`);
      await this.#cache.removeItem(`${cachePrefix}.users.${user.subId}`);
    } catch (err) {
      logger.error('Failed to remove local session.', err);
    }

    this.emitter.dispatchEvent(new CustomEvent('signedOut'));
  }

  /**
   * Start sign in with code process.
   * @param {Object} params
   * @return {Promise<void>}
   * @private
   */
  async #signInCodeStart(params: CodeStartParams): Promise<void> {
    assert(params.email || params.phoneNumber, 'Email or phone number is required');

    // Generate subject DH key pair
    const subDhKeyPair = X25519.generateKeyPair();

    return this.#apiClient
      .request({
        path: Endpoint.START_CODE_SIGN_IN,
        method: HttpMethod.POST,
        headers: {
          [HttpHeader.CONTENT_TYPE]: ContentType.APPLICATION_CBOR
        },
        body: CBOR.encode({
          projectId: this.#projectId,
          dhPubKey: subDhKeyPair.publicKey,
          ...(params.email ? { email: params.email } : { phoneNumber: params.phoneNumber })
        })
      })
      .then(async (response) => {
        if (response.status >= 300) {
          return createServiceException(response);
        }

        const payload = CBOR.decode(new Uint8Array(await response.arrayBuffer()));

        // Compute shared key
        const sharedKey = X25519.sharedKey(subDhKeyPair.secretKey, payload.dhPubKey, true);

        this.#state = {
          sessionId: payload.sessionId,
          sharedKey
        };
      });
  }

  /**
   * Continue sign in with code process.
   * @param {Object} params
   * @return {Promise<void>}
   * @private
   */
  async #signInCodeContinue(params: CodeFinalizeParams): Promise<unknown> {
    assert(this.#state?.sharedKey, 'Must initiate authentication');
    assert(params.code, 'Code is required');

    const code = new Uint8Array(Buffer.from(params.code));

    // Derive shared key
    const derivedSharedKey = scrypt.deriveKey(code, this.#state.sharedKey, 32);

    // Generate subject signing key pair and challenge
    const subSigKeyPair = Ed25519.generateKeyPair();
    const subChallenge = Random.uint8Array(64);

    // Compute data to encrypt
    const data = concatUint8Arrays(subSigKeyPair.publicKey, subChallenge);

    // Encrypt data
    const nonce = Random.uint8Array(24);
    const ciphertext = new Uint8Array(data.length);
    XSalsa20.streamXOR(derivedSharedKey, nonce, data, ciphertext);
    const encrypted = CBOR.encode([
      EMPTY_BUFFER,
      {
        [CoseHeader.alg]: CoseAlgorithm.XSalsa20,
        [CoseHeader.IV]: nonce
      },
      ciphertext
    ] as CoseEncryption);

    return this.#apiClient
      .request({
        path: Endpoint.CONTINUE_CODE_SIGN_IN,
        method: HttpMethod.POST,
        headers: {
          [HttpHeader.CONTENT_TYPE]: ContentType.APPLICATION_CBOR
        },
        body: CBOR.encode({
          sessionId: this.#state.sessionId,
          encrypted
        })
      })
      .then(async (response) => {
        if (response.status >= 300) {
          return createServiceException(response);
        }

        const payload = CBOR.decode(new Uint8Array(await response.arrayBuffer()));

        // Derive shared key
        const derivedSharedKey = scrypt.deriveKey(subChallenge, this.#state.sharedKey, 32);

        // Decode encrypted struct
        const encrypted: CoseEncryption = CBOR.decode(payload.encrypted);

        // Decrypt data
        const data = new Uint8Array(160);

        XSalsa20.streamXOR(
          derivedSharedKey,
          encrypted[1][CoseHeader.IV],
          encrypted[2],
          data
        );

        // Unwrap data
        const issSigPubKey = data.slice(0, 32);
        const issChallenge = data.slice(32, 96);
        const issProof = data.slice(96, 160);

        // Verify issuer proof
        const isProofValid = Ed25519.verify(issSigPubKey, subChallenge, issProof);

        if (!isProofValid) {
          logger.error('Invalid issuer proof');
          throw new Error('Invalid confirmation code');
        }

        // Persist data for finalize
        this.#state = {
          sessionId: this.#state.sessionId,
          sharedKey: this.#state.sharedKey,
          issChallenge: issChallenge,
          issSigPubKey: issSigPubKey,
          subSigPrivKey: subSigKeyPair.secretKey
        };

        return this.#signInCodeFinalize();
      });
  }

  /**
   * Finalize sign in with code process.
   * @return Promise<void>
   * @private
   */
  async #signInCodeFinalize(): Promise<unknown> {
    // Derive shared key
    const derivedSharedKey = scrypt.deriveKey(this.#state.issChallenge, this.#state.sharedKey, 32);

    // Compute data to encrypt
    const data = Ed25519.sign(this.#state.subSigPrivKey, this.#state.issChallenge);

    // Encrypt data
    const nonce = Random.uint8Array(24);
    const ciphertext = new Uint8Array(data.length);
    XSalsa20.streamXOR(derivedSharedKey, nonce, data, ciphertext);
    const encrypted = CBOR.encode([
      EMPTY_BUFFER,
      {
        [CoseHeader.alg]: CoseAlgorithm.XSalsa20,
        [CoseHeader.IV]: nonce
      },
      ciphertext
    ] as CoseEncryption);

    return this.#apiClient
      .request({
        path: Endpoint.FINALIZE_CODE_SIGN_IN,
        method: HttpMethod.POST,
        headers: {
          [HttpHeader.CONTENT_TYPE]: ContentType.APPLICATION_CBOR
        },
        body: CBOR.encode({
          sessionId: this.#state.sessionId,
          encrypted
        })
      })
      .then(async (response) => {
        if (response.status >= 300) {
          return createServiceException(response);
        }

        const payload = CBOR.decode(new Uint8Array(await response.arrayBuffer()));

        const xChaCha20Poly1305 = new XChaCha20Poly1305(this.#state.sharedKey);

        if (payload.status === 'MFA_REQUIRED') {
          const encrypted: CoseEncryption = CBOR.decode(payload.encrypted);

          // Decrypt and decode
          const { factors } = CBOR.decode(xChaCha20Poly1305.open(
            encrypted[1][CoseHeader.IV],
            encrypted[2]
          )) as { factors: Factor[] };

          return {
            status: 'MFA_REQUIRED',
            factors
          };
        }

        if (payload.status === 'AUTHENTICATED') {
          const encrypted: CoseEncryption = CBOR.decode(payload.encrypted);

          // Decrypt and decode authDetails
          const { authDetails } = CBOR.decode(xChaCha20Poly1305.open(
            encrypted[1][CoseHeader.IV],
            encrypted[2]
          )) as { authDetails: AuthDetails };

          // Cleanup internal state
          const subSigPrivKey = this.#state.subSigPrivKey;
          this.#state = null;

          await this.#authenticate({
            issSigAlg: authDetails.issSigAlg,
            issSigKeyId: authDetails.issSigKeyId,
            issSigPubKey: authDetails.issSigPubKey,
            subId: authDetails.subId,
            subSigAlg: authDetails.subSigAlg,
            subSigKeyId: authDetails.subSigKeyId,
            subSigPrivKey,
            projectId: this.#projectId,
            expiresAt: authDetails.expiresAt
          });

          return {
            status: 'AUTHENTICATED'
          };
        }

        throw new Error('Status handler not implemented');
      });
  }

  /**
   * Start sign in with link process.
   * @param {Object} params
   * @return {Promise<void>}
   * @private
   */
  async #signInLinkStart(params: LinkStartParams): Promise<void> {
    assert(params.email, 'Email is required');
    assert(params.redirectUri, 'Redirect URI is required');

    const response = await this.#apiClient.request({
      path: Endpoint.START_LINK_SIGN_IN,
      method: HttpMethod.POST,
      headers: {
        [HttpHeader.CONTENT_TYPE]: ContentType.APPLICATION_CBOR
      },
      body: CBOR.encode({
        projectId: this.#projectId,
        email: params.email,
        redirectUri: params.redirectUri
      })
    });

    if (response.status >= 300) {
      await createServiceException(response);
    }
  }

  /**
   * Finalize sign in with link process.
   * @param {Object} params
   * @return {Promise<void>}
   * @private
   */
  async #signInLinkFinalize(params: LinkFinalizeParams): Promise<unknown> {
    assert(params.token, 'Token is required');

    let token;

    try {
      const rawToken = new Uint8Array(Base64Url.toBuffer(params.token));
      token = CBOR.decode(rawToken);
    } catch (err) {
      logger.error('Unable to decode the token', err);
      throw new Error('Invalid token');
    }

    // Generate subject DH key pair
    const subDhKeyPair = X25519.generateKeyPair();

    // Compute shared key
    const sharedKey = X25519.sharedKey(subDhKeyPair.secretKey, token.dhPubKey, true);

    const xChaCha20Poly1305 = new XChaCha20Poly1305(sharedKey);

    // Generate subject signing key pair and sign the challenge
    const subSigKeyPair = Ed25519.generateKeyPair();
    const subProof = Ed25519.sign(subSigKeyPair.secretKey, token.challenge);

    // Compute data to encrypt
    const data = concatUint8Arrays(subSigKeyPair.publicKey, subProof);

    // Encrypt data
    const nonce = Random.uint8Array(24);
    const ciphertext = xChaCha20Poly1305.seal(nonce, data);
    const encrypted = CBOR.encode([
      EMPTY_BUFFER,
      {
        [CoseHeader.alg]: CoseAlgorithm.xChaCha20Poly1305,
        [CoseHeader.IV]: nonce
      },
      ciphertext
    ] as CoseEncryption);

    return this.#apiClient
      .request({
        path: Endpoint.FINALIZE_LINK_SIGN_IN,
        method: HttpMethod.POST,
        headers: {
          [HttpHeader.CONTENT_TYPE]: ContentType.APPLICATION_CBOR
        },
        body: CBOR.encode({
          sessionId: token.sessionId,
          dhPubKey: subDhKeyPair.publicKey,
          encrypted
        })
      })
      .then(async (response) => {
        if (response.status >= 300) {
          return createServiceException(response);
        }

        const payload = CBOR.decode(new Uint8Array(await response.arrayBuffer()));

        if (payload.status === 'MFA_REQUIRED') {
          const encrypted: CoseEncryption = CBOR.decode(payload.encrypted);

          // Decrypt and decode
          const { factors } = CBOR.decode(xChaCha20Poly1305.open(
            encrypted[1][CoseHeader.IV],
            encrypted[2]
          )) as { factors: Factor[] };

          // Persist data for MFA verification
          this.#state = {
            sessionId: token.sessionId,
            sharedKey,
            subSigPrivKey: subSigKeyPair.secretKey
          };

          return {
            status: 'MFA_REQUIRED',
            factors
          };
        }

        if (payload.status === 'AUTHENTICATED') {
          const encrypted: CoseEncryption = CBOR.decode(payload.encrypted);

          // Decrypt and decode authDetails
          const { authDetails } = CBOR.decode(xChaCha20Poly1305.open(
            encrypted[1][CoseHeader.IV],
            encrypted[2]
          )) as { authDetails: AuthDetails };

          // Cleanup internal state
          this.#state = null;

          await this.#authenticate({
            issSigAlg: authDetails.issSigAlg,
            issSigKeyId: authDetails.issSigKeyId,
            issSigPubKey: authDetails.issSigPubKey,
            subId: authDetails.subId,
            subSigAlg: authDetails.subSigAlg,
            subSigKeyId: authDetails.subSigKeyId,
            subSigPrivKey: subSigKeyPair.secretKey,
            projectId: this.#projectId,
            expiresAt: authDetails.expiresAt
          });

          return {
            status: 'AUTHENTICATED'
          };
        }

        throw new Error('Status handler not implemented');
      });
  }

  /**
   * Authenticate the user internally.
   * @param {any} params
   * @return {Promise<void>}
   * @private
   */
  async #authenticate(params: AuthenticateParams): Promise<void> {
    const credential = new Credential({
      issSigAlg: params.issSigAlg,
      issSigKeyId: params.issSigKeyId,
      issSigPubKey: params.issSigPubKey,
      subId: params.subId,
      subSigAlg: params.subSigAlg,
      subSigKeyId: params.subSigKeyId,
      subSigPrivKey: params.subSigPrivKey,
      projectId: params.projectId,
      expiresAt: params.expiresAt
    });

    this.#user = new User({
      projectId: params.projectId,
      credential
    });

    const cachePrefix = `zalter.auth.${params.projectId}`;

    await this.#cache.setItem(
      `${cachePrefix}.users.${params.subId}`,
      Buffer
        .from(CBOR.encode({
          issSigAlg: params.issSigAlg,
          issSigKeyId: params.issSigKeyId,
          issSigPubKey: params.issSigPubKey,
          subId: params.subId,
          subSigAlg: params.subSigAlg,
          subSigKeyId: params.subSigKeyId,
          subSigPrivKey: params.subSigPrivKey,
          projectId: params.projectId,
          expiresAt: params.expiresAt
        }))
        .toString('base64')
    );

    await this.#cache.setItem(`${cachePrefix}.currentUser`, params.subId);

    // Emit the signed in event
    this.emitter.dispatchEvent(new CustomEvent('signedIn'));
  }
}