import { randomBytes } from "node:crypto";
import { SALT_LENGTH } from ".";

/**
 * Generate a random salt
 * @param cost The cost of the salt
 * @returns salt
 */
export function generateSalt(): Buffer {
  const s = randomBytes(SALT_LENGTH);
  return Buffer.from(s);
}
