const TOLERANCE = 5000;

export class TimeDrifter {
  /** The current clock offset */
  #offset: number = 0;

  readonly #tolerance;

  /**
   * @param {number} [tolerance]
   */
  constructor(tolerance?: number) {
    this.#tolerance = tolerance || TOLERANCE;
  }

  /**
   * Returns the drifted date.
   * @return {Date}
   */
  get date(): Date {
    return this.#offset ? new Date(new Date().getTime() + this.#offset) : new Date();
  };

  /**
   * Updates the current offset and returns whether there was any.
   * @param {Date | string | number} date
   * @return {boolean}
   */
  update(date: Date | string | number): boolean {
    const offset = new Date(date).getTime() - new Date().getTime();
    const modified = Math.abs(this.#offset - offset) > this.#tolerance;

    if (modified) {
      this.#offset = offset;
      return true;
    }

    return false;
  };
}