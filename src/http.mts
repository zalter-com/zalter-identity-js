export enum ContentType {
  APPLICATION_CBOR = 'application/cbor',
  APPLICATION_JSON = 'application/json'
}

export enum HttpHeader {
  AUTHORITY = ':authority',
  CONTENT_TYPE = 'content-type',
  DATE = 'date',
  METHOD = ':method',
  PATH = ':path',
  STATUS = ':status',
  X_ZALTER_SIGNATURE = 'x-zalter-signature',
  X_ZALTER_VERSION = 'x-zalter-version'
}

export enum HttpMethod {
  POST = 'POST'
}

export enum HttpStatus {
  UNAUTHORIZED = 401
}