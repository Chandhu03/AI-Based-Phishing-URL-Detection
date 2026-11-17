/**
 * Memoise an async loader. A failed load is forgotten, so the next call tries
 * again instead of returning the same rejection for the rest of the visit.
 * @template T
 * @param {() => Promise<T>} load
 * @returns {() => Promise<T>}
 */
export function onceUnlessFailed(load) {
  let pending;
  return () =>
    (pending ??= load().catch((error) => {
      pending = undefined;
      throw error;
    }));
}
