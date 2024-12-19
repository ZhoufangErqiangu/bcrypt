import { base642Base64BCrypt, base64BCrypt2Base64 } from "./base64";
import { C_ORIG } from "./constant";
import { crypt } from "./crypt";
import { generateSalt } from "./slat";

export const SALT_LENGTH = 16;

export const GENSALT_DEFAULT_LOG2_ROUNDS = 10;

export const BLOWFISH_NUM_ROUNDS = 16;

export const ALG = "2a";

/**
 * Hash a password using the Bcrypt algorithm
 * @param content password
 * @param cost cost, should be between 4 and 31, default is 10, bigger is slower
 * @param salt salt, must be 16 bytes, base64 encoded, bcrypt alphabet
 * @returns hash
 */
export function hash(
  content: string,
  cost: number = GENSALT_DEFAULT_LOG2_ROUNDS,
  salt?: string,
): string {
  // cost
  if (cost < 4 || cost > 31) {
    throw new Error("Invalid cost");
  }
  const cc = cost.toString(10).padStart(2, "0");
  if (cc.length !== 2) {
    throw new Error("Invalid cost");
  }

  // content
  // Ensure the content is null-terminated
  if (!content.endsWith("\x00")) {
    content += "\x00";
  }
  const p = Buffer.from(content, "utf-8");

  // salt
  const s: Buffer = salt
    ? Buffer.from(base64BCrypt2Base64(salt), "base64")
    : generateSalt();
  if (s.length != SALT_LENGTH) {
    throw new Error("Invalid salt length");
  }
  const ss = base642Base64BCrypt(s.toString("base64"));
  if (ss.length !== 22) {
    throw new Error("Invalid salt");
  }

  // hash
  const h = crypt(p, Uint8Array.from(s), cost);
  const hh = base642Base64BCrypt(
    Buffer.from(h).toString("base64", 0, C_ORIG.length * 4 - 1),
  );
  if (hh.length !== 31) {
    throw new Error("Invalid hash");
  }

  return `$${ALG}$${cc}$${ss}${hh}`;
}

/**
 * Verify a password using the Bcrypt algorithm
 * @param contest password
 * @param existHash hash
 * @returns true if the password is correct
 */
export function verify(contest: string, existHash: string): boolean {
  // check hash length
  if (existHash.length !== 60) {
    return false;
  }

  // check hash format
  const hs = existHash.split("$");
  if (hs.length !== 4) {
    return false;
  }

  // check algorithm
  const alg = hs[1];
  if (alg !== ALG) {
    return false;
  }

  // get cost
  const cost = parseInt(hs[2]);
  if (Number.isNaN(cost) || cost < 4 || cost > 31) {
    return false;
  }

  // get salt
  const salt = hs[3].substring(0, 22);

  return hash(contest, cost, salt) === existHash;
}

export * from "./base64";
export * from "./crypt";
export * from "./slat";
