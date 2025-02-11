import { BASE64_ALPHABET, BASE64_ALPHABET_BCRYPT } from "./constant";

/**
 * Convert base64 to bcrypt base64
 * @param s base64 string
 * @returns bcrypt base64 string
 */
export function base642Base64BCrypt(s: string): string {
  const base64Map = BASE64_ALPHABET.split("").reduce(
    (prev: Record<string, number>, cur: string, idx: number) => {
      prev[cur] = idx;
      return prev;
    },
    {},
  );
  const base64BCryptList = BASE64_ALPHABET_BCRYPT.split("");

  const result: string[] = [];
  for (let i = 0; i < s.length; i += 1) {
    const index = base64Map[s[i]];
    result.push(base64BCryptList[index]);
  }

  return result.join("");
}

/**
 * Convert bcrypt base64 to base64
 * @param s bcrypt base64 string
 * @returns base64 string
 */
export function base64BCrypt2Base64(s: string): string {
  const base64BCryptMap = BASE64_ALPHABET_BCRYPT.split("").reduce(
    (prev: Record<string, number>, cur: string, idx: number) => {
      prev[cur] = idx;
      return prev;
    },
    {},
  );
  const base64List = BASE64_ALPHABET.split("");

  const result: string[] = [];
  for (let i = 0; i < s.length; i += 1) {
    const index = base64BCryptMap[s[i]];
    result.push(base64List[index]);
  }

  return result.join("");
}
