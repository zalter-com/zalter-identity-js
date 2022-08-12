/**
 * Concat Uint8Arrays
 * @param {Uint8Array} inputArrays
 * @return {Uint8Array}
 */
export function concatUint8Arrays(...inputArrays: Uint8Array[]): Uint8Array {
  const neededLength = inputArrays.reduce(
    (sum, buff) => sum + buff.length,
    0
  );
  const outputArray = new Uint8Array(neededLength);
  let offset = 0;

  for (const arr of inputArrays) {
    outputArray.set(arr, offset);
    offset += arr.length;
  }

  return outputArray;
}