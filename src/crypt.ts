import { BLOWFISH_NUM_ROUNDS } from ".";
import { C_ORIG, P_ORIG, S_ORIG } from "./constant";

/**
 * @param content content could be password
 * @param salt salt
 * @param cost cost
 * @returns hash
 */
export function crypt(
  content: Uint8Array,
  salt: Uint8Array,
  cost: number,
): Uint8Array {
  const rounds = 2 ** cost;

  const p = Int32Array.from(P_ORIG);
  const s = Int32Array.from(S_ORIG);
  const c = Array.from(C_ORIG);

  ekskey(content, salt, p, s);

  for (let i = 0; i < rounds; i++) {
    key(content, p, s);
    key(salt, p, s);
  }

  for (let i = 0; i < 64; i += 1) {
    for (let j = 0; j < c.length >> 1; j += 1) {
      encipher(c, j << 1, p, s);
    }
  }

  const res: number[] = [];
  for (let i = 0; i < c.length; i += 1) {
    res.push(((c[i] >> 24) & 0xff) >>> 0);
    res.push(((c[i] >> 16) & 0xff) >>> 0);
    res.push(((c[i] >> 8) & 0xff) >>> 0);
    res.push((c[i] & 0xff) >>> 0);
  }

  return Uint8Array.from(res);
}

/**
 * read 4 bytes from data cyclically
 * @param data data
 * @param offset offset
 * @returns 4 bytes
 */
export function stream2Word(data: Uint8Array, offset: number): number {
  let r = 0;
  for (let i = 0; i < 4; i += 1) {
    const ii = (offset + i) % data.length;
    // left shift 8 bits and add the next byte
    r = (r << 8) | data[ii];
  }
  return r;
}

/**
 * @param lr lr will be modified
 * @param offset offset
 * @param P P
 * @param S S
 * @returns lr
 */
export function encipher(
  lr: number[],
  offset: number,
  P: Int32Array,
  S: Int32Array,
): number[] {
  let l = lr[offset];
  let r = lr[offset + 1];

  l ^= P[0];

  // interation 0
  let n = S[l >>> 24];
  n += S[0x100 | ((l >> 16) & 0xff)];
  n ^= S[0x200 | ((l >> 8) & 0xff)];
  n += S[0x300 | (l & 0xff)];
  r ^= n ^ P[1];
  n = S[r >>> 24];
  n += S[0x100 | ((r >> 16) & 0xff)];
  n ^= S[0x200 | ((r >> 8) & 0xff)];
  n += S[0x300 | (r & 0xff)];
  l ^= n ^ P[2];
  // interation 1
  n = S[l >>> 24];
  n += S[0x100 | ((l >> 16) & 0xff)];
  n ^= S[0x200 | ((l >> 8) & 0xff)];
  n += S[0x300 | (l & 0xff)];
  r ^= n ^ P[3];
  n = S[r >>> 24];
  n += S[0x100 | ((r >> 16) & 0xff)];
  n ^= S[0x200 | ((r >> 8) & 0xff)];
  n += S[0x300 | (r & 0xff)];
  l ^= n ^ P[4];
  // interation 2
  n = S[l >>> 24];
  n += S[0x100 | ((l >> 16) & 0xff)];
  n ^= S[0x200 | ((l >> 8) & 0xff)];
  n += S[0x300 | (l & 0xff)];
  r ^= n ^ P[5];
  n = S[r >>> 24];
  n += S[0x100 | ((r >> 16) & 0xff)];
  n ^= S[0x200 | ((r >> 8) & 0xff)];
  n += S[0x300 | (r & 0xff)];
  l ^= n ^ P[6];
  // interation 3
  n = S[l >>> 24];
  n += S[0x100 | ((l >> 16) & 0xff)];
  n ^= S[0x200 | ((l >> 8) & 0xff)];
  n += S[0x300 | (l & 0xff)];
  r ^= n ^ P[7];
  n = S[r >>> 24];
  n += S[0x100 | ((r >> 16) & 0xff)];
  n ^= S[0x200 | ((r >> 8) & 0xff)];
  n += S[0x300 | (r & 0xff)];
  l ^= n ^ P[8];
  // interation 4
  n = S[l >>> 24];
  n += S[0x100 | ((l >> 16) & 0xff)];
  n ^= S[0x200 | ((l >> 8) & 0xff)];
  n += S[0x300 | (l & 0xff)];
  r ^= n ^ P[9];
  n = S[r >>> 24];
  n += S[0x100 | ((r >> 16) & 0xff)];
  n ^= S[0x200 | ((r >> 8) & 0xff)];
  n += S[0x300 | (r & 0xff)];
  l ^= n ^ P[10];
  // interation 5
  n = S[l >>> 24];
  n += S[0x100 | ((l >> 16) & 0xff)];
  n ^= S[0x200 | ((l >> 8) & 0xff)];
  n += S[0x300 | (l & 0xff)];
  r ^= n ^ P[11];
  n = S[r >>> 24];
  n += S[0x100 | ((r >> 16) & 0xff)];
  n ^= S[0x200 | ((r >> 8) & 0xff)];
  n += S[0x300 | (r & 0xff)];
  l ^= n ^ P[12];
  // interation 6
  n = S[l >>> 24];
  n += S[0x100 | ((l >> 16) & 0xff)];
  n ^= S[0x200 | ((l >> 8) & 0xff)];
  n += S[0x300 | (l & 0xff)];
  r ^= n ^ P[13];
  n = S[r >>> 24];
  n += S[0x100 | ((r >> 16) & 0xff)];
  n ^= S[0x200 | ((r >> 8) & 0xff)];
  n += S[0x300 | (r & 0xff)];
  l ^= n ^ P[14];
  // interation 7
  n = S[l >>> 24];
  n += S[0x100 | ((l >> 16) & 0xff)];
  n ^= S[0x200 | ((l >> 8) & 0xff)];
  n += S[0x300 | (l & 0xff)];
  r ^= n ^ P[15];
  n = S[r >>> 24];
  n += S[0x100 | ((r >> 16) & 0xff)];
  n ^= S[0x200 | ((r >> 8) & 0xff)];
  n += S[0x300 | (r & 0xff)];
  l ^= n ^ P[16];

  lr[offset] = r ^ P[BLOWFISH_NUM_ROUNDS + 1];
  lr[offset + 1] = l;

  return lr;
}

/**
 * @param content password
 * @param salt salt
 * @param P P will be modified
 * @param S S will be modified
 */
export function ekskey(
  content: Uint8Array,
  salt: Uint8Array,
  P: Int32Array,
  S: Int32Array,
): void {
  for (let i = 0; i < P.length; i += 1) {
    const oo = i * 4;
    const key = stream2Word(content, oo);
    P[i] ^= key;
  }

  let lr = [0, 0];
  let o = 0;
  for (let i = 0; i < P.length; i += 2) {
    const k1 = stream2Word(salt, o);
    o += 4;
    lr[0] ^= k1;
    const k2 = stream2Word(salt, o);
    o += 4;
    lr[1] ^= k2;
    lr = encipher(lr, 0, P, S);
    P[i] = lr[0];
    P[i + 1] = lr[1];
  }

  for (let i = 0; i < S.length; i += 2) {
    const k1 = stream2Word(salt, o);
    o += 4;
    lr[0] ^= k1;
    const k2 = stream2Word(salt, o);
    o += 4;
    lr[1] ^= k2;
    lr = encipher(lr, 0, P, S);
    S[i] = lr[0];
    S[i + 1] = lr[1];
  }
}

/**
 * @param data password or salt
 * @param P P will be modified
 * @param S S will be modified
 */
export function key(data: Uint8Array, P: Int32Array, S: Int32Array): void {
  let lr = [0, 0];

  for (let i = 0; i < P.length; i += 1) {
    const k = stream2Word(data, i * 4);
    P[i] ^= k;
  }

  for (let i = 0; i < P.length; i += 2) {
    lr = encipher(lr, 0, P, S);
    P[i] = lr[0];
    P[i + 1] = lr[1];
  }

  for (let i = 0; i < S.length; i += 2) {
    lr = encipher(lr, 0, P, S);
    S[i] = lr[0];
    S[i + 1] = lr[1];
  }
}
