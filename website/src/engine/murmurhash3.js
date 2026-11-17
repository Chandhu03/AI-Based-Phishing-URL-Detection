// MurmurHash3 x86 32-bit over bytes, returning a SIGNED 32-bit integer.
// Matches sklearn.utils.murmurhash3_32(key, seed, positive=False), which is
// what scikit-learn's HashingVectorizer uses.

const C1 = 0xcc9e2d51;
const C2 = 0x1b873593;

/**
 * @param {Uint8Array} bytes
 * @param {number} [seed]
 * @returns {number} signed 32-bit hash
 */
export function murmurhash3_32(bytes, seed = 0) {
  let h = seed >>> 0;
  const len = bytes.length;
  const blocks = len & ~3;
  for (let i = 0; i < blocks; i += 4) {
    let k = bytes[i] | (bytes[i + 1] << 8) | (bytes[i + 2] << 16) | (bytes[i + 3] << 24);
    k = Math.imul(k, C1);
    k = (k << 15) | (k >>> 17);
    k = Math.imul(k, C2);
    h ^= k;
    h = (h << 13) | (h >>> 19);
    h = (Math.imul(h, 5) + 0xe6546b64) | 0;
  }
  let k = 0;
  switch (len & 3) {
    case 3: k ^= bytes[blocks + 2] << 16; // falls through
    case 2: k ^= bytes[blocks + 1] << 8; // falls through
    case 1:
      k ^= bytes[blocks];
      k = Math.imul(k, C1);
      k = (k << 15) | (k >>> 17);
      k = Math.imul(k, C2);
      h ^= k;
  }
  h ^= len;
  h ^= h >>> 16;
  h = Math.imul(h, 0x85ebca6b);
  h ^= h >>> 13;
  h = Math.imul(h, 0xc2b2ae35);
  h ^= h >>> 16;
  return h | 0;
}
