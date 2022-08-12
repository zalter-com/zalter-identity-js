import * as CBOR from '@stablelib/cbor';
import { ContentType, HttpHeader } from './http.mjs';

export class ServiceException extends Error {
  /**
   * @type string
   */
  code: string;

  /**
   * @param {object} options
   * @param {string} options.code
   * @param {string} options.message
   */
  constructor(options) {
    super(options.message);
    this.code = options.code;
  }

  toJSON() {
    return {
      code: this.code,
      message: this.message
    };
  }
}

/**
 * @param {Response} response
 * @return {Promise<never>}
 * @throws ServiceException
 */
export async function createServiceException(response: Response): Promise<never> {
  let body;

  try {
    switch (response.headers.get(HttpHeader.CONTENT_TYPE)) {
      case ContentType.APPLICATION_CBOR: {
        body = CBOR.decode(new Uint8Array(await response.arrayBuffer()));
        break;
      }

      case ContentType.APPLICATION_JSON: {
        body = await response.json();
        break;
      }
    }
  } catch {}

  throw new ServiceException({
    code: body?.error?.code || 'unknown_error',
    message: body?.error?.message || 'Something went wrong'
  });
}