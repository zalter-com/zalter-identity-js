export const LOG_LEVELS = {
  VERBOSE: 1,
  DEBUG: 2,
  INFO: 3,
  WARN: 4,
  ERROR: 5
};

export class Logger {
  readonly #prefix: string;
  readonly #level: number;

  /**
   * @param config
   * @param {string} prefix
   * @param {number} [config.level]
   */
  constructor(prefix: string, config?: { level: number }) {
    this.#prefix = prefix;

    if (config?.level) {
      this.#level = config.level;
    }

    try {
      const storedLevel = parseInt(globalThis.sessionStorage.getItem('zalter.logLevel'), 10);

      if (storedLevel) {
        this.#level = storedLevel;
      }
    } catch {}

    this.#level = this.#level || LOG_LEVELS.VERBOSE;
  }

  verbose(...args) {
    this.#write('VERBOSE', ...args);
  }

  debug(...args) {
    this.#write('DEBUG', ...args);
  }

  info(...args) {
    this.#write('INFO', ...args);
  }

  warn(...args) {
    this.#write('WARN', ...args);
  }

  error(...args) {
    this.#write('ERROR', ...args);
  }

  #write(type, ...args) {
    if (LOG_LEVELS[type] < this.#level) {
      return;
    }

    let fn = console.log.bind(console);

    if (type === 'ERROR') {
      fn = console.error.bind(console);
    }

    if (type === 'WARN') {
      fn = console.warn.bind(console);
    }

    fn(`[${this.#prefix}]`, ...args);
  }
}