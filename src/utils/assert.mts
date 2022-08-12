export const assert = (value: any, msg: string) => {
  if (!value) {
    throw new Error(msg);
  }
};