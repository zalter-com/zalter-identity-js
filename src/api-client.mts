import * as CBOR from '@stablelib/cbor';
import { default as Base64Url } from 'base64url';
import { Auth } from './auth.mjs';
import { API_VERSION } from './constants.mjs';
import { HttpHeader, HttpStatus } from './http.mjs';
import { Logger } from './logger.mjs';
import { TimeDrifter } from './time-drifter.mjs';
import { User } from './user.mjs';
import { concatUint8Arrays } from './utils/concat-uint8arrays.mjs';

if (!globalThis.fetch) {
  throw new Error('No global fetch implementation found.');
}

const logger = new Logger('API Client');

interface RequestParams {
  body?: string | ArrayBuffer | DataView | Uint8Array;
  headers?: Record<string, any>;
  method?: string;
  path?: string;
  options?: {
    signRequest?: boolean;
    verifyResponse?: boolean;
  };
}

interface Request {
  authority: string;
  body?: string | ArrayBuffer | DataView | Uint8Array;
  headers?: Record<string, any>;
  method?: string;
  path?: string;
  scheme: 'http' | 'https';
}

interface SignOptions {
  now?: number;
  expiresIn?: number;
}

interface VerifyOptions {
  now?: number;
  maxAge?: number;
}

const addBaseHeaders = (headers?: Record<string, any>): Record<string, any> => {
  return Object.assign({}, headers, {
    [HttpHeader.X_ZALTER_VERSION]: API_VERSION
  });
};

interface ApiClientConfig {
  auth: Auth;
  endpoint: {
    authority: string;
    scheme: 'http' | 'https';
  };
  timeDrifter: TimeDrifter;
}

export class ApiClient {
  readonly #auth: Auth;

  readonly #endpoint: {
    authority: string;
    scheme: 'http' | 'https';
  };

  readonly #timeDrifter: TimeDrifter;

  /**
   * @param {object} config
   */
  constructor(config: ApiClientConfig) {
    if (!(config.auth instanceof Auth)) {
      throw Error('auth must be an instance of Auth');
    }

    if (!(config.timeDrifter instanceof TimeDrifter)) {
      throw Error('timeDrifter must be an instance of TimeDrifter');
    }

    if (typeof config.endpoint === 'undefined') {
      throw new Error('Authority must be provided');
    }

    this.#auth = config.auth;
    this.#endpoint = config.endpoint;
    this.#timeDrifter = config.timeDrifter;
  }

  /**
   * Performs the API call.
   * @param {object} params
   * @return {Promise<Response>}
   */
  async request(params: RequestParams): Promise<Response> {
    const request = {
      authority: this.#endpoint.authority,
      body: params.body,
      headers: addBaseHeaders(params.headers),
      method: params.method,
      path: params.path,
      scheme: this.#endpoint.scheme
    };

    let user;

    if (params.options?.signRequest || params.options?.verifyResponse) {
      try {
        user = await this.#auth.getCurrentUser();
      } catch (err) {
        logger.error(err);
      }

      if (!user) {
        throw new Error('Must be signed in to sign the request.');
      }
    }

    // Sign the request.

    if (params.options?.signRequest) {
      await this.#signRequest(request, user, {
        now: Math.floor(this.#timeDrifter.date.getTime() / 1000)
      });
    }

    let response;

    try {
      response = await fetch(
        request.scheme + '://' + request.authority + request.path,
        {
          body: request.body,
          headers: request.headers,
          method: request.method
        }
      );
    } catch (err) {
      logger.error(err);
      throw new Error('Something went wrong');
    }

    // Might be a drift
    if (params.options?.signRequest && response.status === HttpStatus.UNAUTHORIZED) {
      const date = response.headers.get(HttpHeader.DATE);

      if (this.#timeDrifter.update(date)) {
        response = await this.request(params);
      }
    }

    if (response.status >= 300) {
      return response;
    }

    if (!params.options?.verifyResponse) {
      return response;
    }

    // Verify response signature.

    if (params.options?.verifyResponse) {
      const responseClone = response.clone();
      const isValid = await this.#verifyResponse(responseClone, user);

      if (!isValid) {
        throw new Error('Response couldn\'t be verified');
      }
    }

    return response;
  }

  /**
   * @param {Object} request
   * @param {User} user
   * @param {any} [options]
   */
  async #signRequest(request: Request, user: User, options?: SignOptions): Promise<void> {
    options = options || {};

    const alg = user.subSigAlg;
    const keyId = user.subSigKeyId;
    let created: number = Math.floor(Date.now() / 1000);
    let expires: number | undefined;

    if (typeof options.now !== 'undefined') {
      if (typeof options.now !== 'number') {
        throw new Error('\'now\' should be a number of seconds');
      } else {
        created = options.now;
      }
    }

    if (typeof options.expiresIn !== 'undefined') {
      if (typeof options.expiresIn !== 'number') {
        throw new Error('\'expiresIn\' should be a number of seconds');
      } else {
        expires = created + options.expiresIn;
      }
    }

    // Map request data to http headers for http2 protocol.

    const headers = {
      ...request.headers,
      [HttpHeader.AUTHORITY]: request.authority,
      [HttpHeader.METHOD]: request.method,
      [HttpHeader.PATH]: request.path
    };

    // We have no control over other headers added by browsers, proxies or other network interceptors.

    const signedHeaders = Object.keys(headers).sort();

    const sortedHeaders = signedHeaders.reduce((acc, key) => {
      acc[key] = headers[key];
      return acc;
    }, {});

    let body;

    if (typeof request.body === 'undefined') {
      body = new Uint8Array(0);
    } else if (typeof request.body === 'string') {
      body = new TextEncoder().encode(request.body);
    } else if (request.body instanceof Uint8Array) {
      body = request.body;
    } else if (request.body instanceof ArrayBuffer) {
      body = new Uint8Array(request.body);
    } else if (request.body.buffer instanceof ArrayBuffer) {
      body = new Uint8Array(request.body.buffer);
    } else {
      throw new Error('\'body\' must be string, ArrayBuffer or TypedArray');
    }

    const dataToSign = concatUint8Arrays(
      CBOR.encode({
        alg,
        keyId,
        created,
        expires,
        signedHeaders
      }),
      CBOR.encode(sortedHeaders),
      body
    );

    const sig = user.signMessage(dataToSign);

    const signature = {
      alg,
      keyId,
      created,
      expires,
      signedHeaders,
      sig
    };

    request.headers[HttpHeader.X_ZALTER_SIGNATURE] = Base64Url.fromBase64(
      Buffer.from(CBOR.encode(signature)).toString('base64')
    );
  }

  /**
   * @param {Response} response
   * @param {User} user
   * @param {any} [options]
   * @return {boolean}
   */
  async #verifyResponse(response: Response, user: User, options?: VerifyOptions): Promise<boolean> {
    options = options || {};

    const signatureHeader = response.headers.get(HttpHeader.X_ZALTER_SIGNATURE);

    if (!signatureHeader) {
      logger.error('Missing signature header');
      return false;
    }

    let signature;

    try {
      signature = CBOR.decode(Buffer.from(Base64Url.toBase64(signatureHeader), 'base64'));
    } catch {
      logger.error('Invalid signature header');
      return false;
    }

    let now = Math.floor(Date.now() / 1000);

    if (typeof options.now !== 'undefined') {
      if (typeof options.now !== 'number') {
        throw new Error('\'now\' should be a number');
      } else {
        now = options.now;
      }
    }

    // TODO: Verify signature.created and signature.expires are not before now when defined

    if (typeof signature.expires !== 'undefined') {
      if (typeof signature.expires !== 'number') {
        logger.error('Invalid \'expires\' value');
        return false;
      }
    }

    if (typeof options.maxAge !== 'undefined') {
      if (typeof options.maxAge !== 'number') {
        throw new Error('\'maxAge\' should be a number of seconds');
      }

      if (typeof signature.created !== 'number') {
        logger.error('\'maxAge\' specified but \'created\' value missing or invalid');
        return false;
      }

      if (now >= signature.created + options.maxAge) {
        logger.error('\'maxAge\' exceeded');
        return false;
      }
    }

    if (signature.alg !== 'Ed25519') {
      logger.error('Invalid \'alg\' value');
      return false;
    }

    if (signature.keyId && typeof signature.keyId !== 'string') {
      logger.error('Invalid \'keyId\' value');
      return false;
    }

    if (!(signature.sig instanceof Uint8Array)) {
      logger.error('Invalid \'sig\' value');
      return false;
    }

    if (
      !(Array.isArray(signature.signedHeaders)) ||
      !signature.signedHeaders.every((item) => (typeof item === 'string'))
    ) {
      logger.error('Invalid \'signature.signedHeaders\' value');
      return false;
    }

    // @ts-ignore
    const headers = Object.fromEntries(response.headers.entries());

    // Map response data to http headers for http2 protocol

    headers[HttpHeader.STATUS] = response.status;

    const signedHeadersData = (signature.signedHeaders || []).reduce((acc, key) => {
      acc[key] = headers[key];
      return acc;
    }, {});

    const body = new Uint8Array(await response.arrayBuffer());

    const dataToVerify = concatUint8Arrays(
      CBOR.encode({
        alg: signature.alg,
        keyId: signature.keyId,
        created: signature.created,
        expires: signature.expires,
        signedHeaders: signature.signedHeaders
      }),
      CBOR.encode(signedHeadersData),
      body
    );

    // TODO: Verify keyId is known by the user

    try {
      return user.verifyMessage(dataToVerify, signature.sig);
    } catch (err) {
      logger.error('Invalid signature', err);
      return false;
    }
  }
}