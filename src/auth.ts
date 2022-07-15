import * as CBOR from '@stablelib/cbor';
import * as Ed25519 from '@stablelib/ed25519';
import * as X25519 from '@stablelib/x25519';
import * as XSalsa20 from '@stablelib/xsalsa20';
import { XChaCha20Poly1305 } from '@stablelib/xchacha20poly1305';
import { Scrypt } from '@stablelib/scrypt';
import { Buffer } from 'buffer';
import { EventEmitter } from './event-emitter';
import { ApiClient } from './api-client';
import { BASE_ENDPOINT } from './constants';
import { Session } from './session';
import { ContentType, HttpHeader, HttpMethod } from './http';
import { createServiceException } from './exception';
import { Logger } from './logger';
import { Cache, getCache } from './cache';
import { TimeDrifter } from './time-drifter';
import { User } from './user';
import { concatUint8Arrays } from './utils/concat-uint8arrays';
import { Random } from './utils/random';

const scrypt = new Scrypt(4096, 4, 1);

const logger = new Logger('Auth');

enum Endpoint {
  START_CODE_SIGN_IN = '/v1/auth/signInWithCode:start',
  CONTINUE_CODE_SIGN_IN = '/v1/auth/signInWithCode:continue',
  FINALIZE_CODE_SIGN_IN = '/v1/auth/signInWithCode:finalize',
  START_LINK_SING_IN = '/v1/auth/signInWithLink:start',
  FINALIZE_LINK_SING_IN = '/v1/auth/signInWithLink:finalize',
  SIGN_OUT = '/v1/account/sessions:deleteCurrent'
}

type CodeFlow = 'start' | 'finalize';

type LinkFlow = 'start' | 'finalize';

interface CodeStartParams {
  email?: string;
}

interface CodeFinalizeParams {
  code: string;
}

interface LinkStartParams {
  email?: string;
  confirmUrl?: string;
}

interface LinkFinalizeParams {
  token?: string;
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

  /** Internal session state during code authentication strategy process */
  #context: Record<any, any> | null = null;

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

        // TODO: Check if session expired

        const session = new Session({
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
          session
        });
      } catch (err) {
        logger.error('Unable to decode the session, removing it from cache.', err);
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
  signInWithCode(flow: CodeFlow, params: CodeStartParams | CodeFinalizeParams): Promise<void> {
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
  signInWithLink(flow: LinkFlow, params: LinkStartParams | LinkFinalizeParams): Promise<void> {
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
    const { email } = params;

    return this.#apiClient
      .request({
        path: Endpoint.START_CODE_SIGN_IN,
        method: HttpMethod.POST,
        headers: {
          [HttpHeader.CONTENT_TYPE]: ContentType.APPLICATION_CBOR
        },
        body: CBOR.encode({
          projectId: this.#projectId,
          email
        })
      })
      .then(async (response) => {
        if (response.status >= 300) {
          return createServiceException(response);
        }

        const payload = CBOR.decode(new Uint8Array(await response.arrayBuffer())) as {
          sessionId: string;
          kex: {
            issDHPubKey: Uint8Array;
          };
        };

        this.#context = {
          sessionId: payload.sessionId,
          issDHPubKey: payload.kex.issDHPubKey
        };
      });
  }

  /**
   * Continue sign in with code process.
   * @param {Object} params
   * @return {Promise<void>}
   * @private
   */
  async #signInCodeContinue(params: CodeFinalizeParams): Promise<void> {
    const { code } = params;

    if (!this.#context?.issDHPubKey) {
      throw new Error('Must initiate authentication');
    }

    const rawCode = new Uint8Array(Buffer.from(code));

    // Generate subject DH key pair
    const subDHKeyPair = X25519.generateKeyPair();

    // Compute base DH key
    const dhKey = X25519.sharedKey(subDHKeyPair.secretKey, this.#context.issDHPubKey, true);

    // Derive DH key
    const derivedDHKey = scrypt.deriveKey(rawCode, dhKey, 32);

    // Generate subject signing key pair and challenge
    const subSigKeyPair = Ed25519.generateKeyPair();
    const subChallenge = Random.uint8Array(64);

    // Compute kex data
    const kexData = concatUint8Arrays(subSigKeyPair.publicKey, subChallenge);

    // Encrypt kex data
    const kexNonce = Random.uint8Array(24);
    XSalsa20.streamXOR(derivedDHKey, kexNonce, kexData, kexData);

    return this.#apiClient
      .request({
        path: Endpoint.CONTINUE_CODE_SIGN_IN,
        method: HttpMethod.POST,
        headers: {
          [HttpHeader.CONTENT_TYPE]: ContentType.APPLICATION_CBOR
        },
        body: CBOR.encode({
          sessionId: this.#context.sessionId,
          kex: {
            subDHPubKey: subDHKeyPair.publicKey,
            nonce: kexNonce,
            data: kexData
          }
        })
      })
      .then(async (response) => {
        if (response.status >= 300) {
          return createServiceException(response);
        }

        const payload = CBOR.decode(new Uint8Array(await response.arrayBuffer())) as {
          kex: {
            nonce: Uint8Array;
            data: Uint8Array;
          };
        };

        // Derive DH key
        const derivedDHKey = scrypt.deriveKey(subChallenge, dhKey, 32);

        // Decode kex values
        const kexData = new Uint8Array(payload.kex.data.length);

        // Decrypt kex data
        XSalsa20.streamXOR(derivedDHKey, payload.kex.nonce, payload.kex.data, kexData);

        if (kexData.length !== 160) {
          logger.error('Invalid ked length');
          throw new Error('Something went wrong');
        }

        // Unwrap kex data
        const issSigPubKey = kexData.slice(0, 32);
        const issChallenge = kexData.slice(32, 96);
        const issProof = kexData.slice(96, 160);

        // Verify issuer proof
        const isProofValid = Ed25519.verify(issSigPubKey, subChallenge, issProof);

        if (!isProofValid) {
          logger.error('Invalid issuer proof');
          throw new Error('Invalid confirmation code');
        }

        this.#context.issChallenge = issChallenge;
        this.#context.issSigPubKey = issSigPubKey;
        this.#context.subSigPrivKey = subSigKeyPair.secretKey;
        this.#context.dhKey = dhKey;

        return this.#signInCodeFinalize();
      });
  }

  /**
   * Finalize sign in with code process.
   * @return Promise<void>
   * @private
   */
  async #signInCodeFinalize(): Promise<void> {
    // Derive DH key
    const derivedDHKey = scrypt.deriveKey(this.#context.issChallenge, this.#context.dhKey, 32);

    // Compute kex data
    const kexData = Ed25519.sign(this.#context.subSigPrivKey, this.#context.issChallenge);

    // Encrypt kex data
    const kexNonce = Random.uint8Array(24);
    XSalsa20.streamXOR(derivedDHKey, kexNonce, kexData, kexData);

    return this.#apiClient
      .request({
        path: Endpoint.FINALIZE_CODE_SIGN_IN,
        method: HttpMethod.POST,
        headers: {
          [HttpHeader.CONTENT_TYPE]: ContentType.APPLICATION_CBOR
        },
        body: CBOR.encode({
          sessionId: this.#context.sessionId,
          kex: {
            nonce: kexNonce,
            data: kexData
          }
        })
      })
      .then(async (response) => {
        if (response.status >= 300) {
          return createServiceException(response);
        }

        const payload = CBOR.decode(new Uint8Array(await response.arrayBuffer())) as {
          nonce: Uint8Array;
          data: Uint8Array;
        };

        // Decrypt response data
        const xChaCha20Poly1305 = new XChaCha20Poly1305(this.#context.dhKey);
        const data = xChaCha20Poly1305.open(payload.nonce, payload.data);

        // Decode response data
        const { session } = CBOR.decode(data);

        const subSigPrivKey = this.#context.subSigPrivKey;

        // Cleanup internal session
        this.#context = null;

        return this.#authenticate({
          issSigAlg: session.issSigAlg,
          issSigKeyId: session.issSigKeyId,
          issSigPubKey: session.issSigPubKey,
          subId: session.subId,
          subSigAlg: session.subSigAlg,
          subSigKeyId: session.subSigKeyId,
          subSigPrivKey,
          projectId: this.#projectId,
          expiresAt: session.expiresAt
        });
      });
  }

  /**
   * Start sign in with link process.
   * @param {Object} params
   * @return {Promise<void>}
   * @private
   */
  async #signInLinkStart(params: LinkStartParams): Promise<void> {
    const { email, confirmUrl } = params;

    const response = await this.#apiClient.request({
      path: Endpoint.START_LINK_SING_IN,
      method: HttpMethod.POST,
      headers: {
        [HttpHeader.CONTENT_TYPE]: ContentType.APPLICATION_CBOR
      },
      body: CBOR.encode({
        projectId: this.#projectId,
        email,
        confirmUrl
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
  async #signInLinkFinalize(params: LinkFinalizeParams): Promise<void> {
    const { token: encodedToken } = params;

    let token;

    try {
      const rawToken = new Uint8Array(Buffer.from(decodeURIComponent(encodedToken), 'base64'));
      token = CBOR.decode(rawToken);
    } catch {
      logger.error('Unable to decode the token');
      throw new Error('Invalid token');
    }

    // Generate subject DH key pair
    const subDHKeyPair = X25519.generateKeyPair();

    // Compute DH key
    const dhKey = X25519.sharedKey(subDHKeyPair.secretKey, token.issDHPubKey, true);

    const xChaCha20Poly1305 = new XChaCha20Poly1305(dhKey);

    // Generate subject signing key pair and sign the challenge
    const subSigKeyPair = Ed25519.generateKeyPair();
    const subProof = Ed25519.sign(subSigKeyPair.secretKey, token.challenge);

    // Compute kex data
    let kexData = concatUint8Arrays(subSigKeyPair.publicKey, subProof);

    // Encrypt kex data
    const kexNonce = Random.uint8Array(24);
    kexData = xChaCha20Poly1305.seal(kexNonce, kexData);

    return this.#apiClient
      .request({
        path: Endpoint.FINALIZE_LINK_SING_IN,
        method: HttpMethod.POST,
        headers: {
          [HttpHeader.CONTENT_TYPE]: ContentType.APPLICATION_CBOR
        },
        body: CBOR.encode({
          sessionId: token.sessionId,
          kex: {
            subDHPubKey: subDHKeyPair.publicKey,
            nonce: kexNonce,
            data: kexData
          }
        })
      })
      .then(async (response) => {
        if (response.status >= 300) {
          return createServiceException(response);
        }

        const payload = CBOR.decode(new Uint8Array(await response.arrayBuffer())) as {
          nonce: Uint8Array;
          data: Uint8Array;
        };

        // Decrypt response data
        const data = xChaCha20Poly1305.open(payload.nonce, payload.data);

        // Decode response data
        const { session } = CBOR.decode(data);

        return this.#authenticate({
          issSigAlg: session.issSigAlg,
          issSigKeyId: session.issSigKeyId,
          issSigPubKey: session.issSigPubKey,
          subId: session.subId,
          subSigAlg: session.subSigAlg,
          subSigKeyId: session.subSigKeyId,
          subSigPrivKey: subSigKeyPair.secretKey,
          projectId: this.#projectId,
          expiresAt: session.expiresAt
        });
      });
  }

  /**
   * Authenticate the user internally.
   * @param {any} params
   * @return {Promise<void>}
   * @private
   */
  async #authenticate(params: any): Promise<void> {
    const session = new Session({
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
      session
    });

    // Persist the auth session
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