/**
 * Cross-platform (web and Node.js) asynchronous event target with debounce capabilities.
 */
export class EventEmitter {
  /**
   * Registry container for event handlers
   * @type {Map}
   * @private
   */
  #registry = new Map();

  /**
   * Requested invoke handle produced by either requestAnimation (for web) or requestImmediate (for Node.js).
   * @private
   */
  #invokerHandle;

  /**
   * Static method that does the actual dispatching.
   * @note This is made so that we avoid overloading the stack and referencing in each object.
   * @param {CustomEvent} event
   */
  dispatchEvent(event) {
    const fn = () => {
      if (this.#registry.get(event.type) instanceof Set) {
        for (const handler of this.#registry.get(event.type)) {
          handler(event);
        }
      }

      this.#invokerHandle = undefined;
    };

    if (typeof globalThis.requestAnimationFrame === 'function') {
      if (this.#invokerHandle) {
        globalThis.cancelAnimationFrame(this.#invokerHandle);
      }

      this.#invokerHandle = globalThis.requestAnimationFrame(fn);
    } else if (typeof globalThis.setImmediate === 'function') {
      if (this.#invokerHandle) {
        globalThis.clearImmediate(this.#invokerHandle);
      }

      this.#invokerHandle = globalThis.setImmediate(fn);
    } else {
      throw new Error('Unable to run events.');
    }
  }

  /**
   * Add event listener for the provided type.
   * @param {string} type
   * @param {function} handler
   */
  addEventListener(type, handler) {
    if (typeof this.#registry.get(type) === 'object' && this.#registry.get(type) instanceof Set) {
      this.#registry.get(type).add(handler);
    } else {
      this.#registry.set(type, new Set([handler]));
    }
  }

  /**
   * Removes the provided event listener for the given type.
   * @param {string} type
   * @param {function} handler
   */
  removeEventListener(type, handler) {
    const listeners = this.#registry.get(type);

    if (listeners instanceof Set) {
      listeners.delete(handler);
    }
  }
}