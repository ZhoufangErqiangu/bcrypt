import { notEqual, strictEqual } from "node:assert";
import test, { describe } from "node:test";
import {
  GENSALT_DEFAULT_LOG2_ROUNDS,
  base642Base64BCrypt,
  base64BCrypt2Base64,
  crypt,
  ekskey,
  encipher,
  generateSalt,
  hash,
  key,
  stream2Word,
  verify,
} from "../src";
import { P_ORIG, S_ORIG } from "../src/constant";

// 4f ce 3f f4 71 ae ca c2 b3 cf f1 28 29 20 db 9d
// T84/9HGuysKzz/EoKSDbnQ==
const TEST_SALT = "T84/9HGuysKzz/EoKSDbnQ";
// 70 61 73 73 77 6f 72 64 31 32 33
const TEST_PASSWORD = "password123";

describe("bcrypt unit test", () => {
  test("base64", () => {
    const b = base642Base64BCrypt(TEST_SALT);
    strictEqual(b, "R6297FEswqIxx9CmIQBZlO");
    const bb = base64BCrypt2Base64(b);
    strictEqual(bb, TEST_SALT);
  });
  test("generate salt", () => {
    const s1 = generateSalt();
    const s2 = generateSalt();
    notEqual(s1, s2, "Salt should be different");
  });
  test("stream to word", () => {
    const p = Uint8Array.from(Buffer.from(TEST_PASSWORD, "utf-8"));
    const r1 = stream2Word(p, 0);
    strictEqual(r1, 0x70617373, "First word should be 0x70617373");
    const r2 = stream2Word(p, 4);
    strictEqual(r2, 0x776f7264, "Second word should be 0x776f7264");
    const r3 = stream2Word(p, 8);
    strictEqual(r3, 0x31323370, "Third word should be 0x31323370");
    const r4 = stream2Word(p, 12);
    strictEqual(r4, 0x61737377, "Fourth word should be 0x61737377");
    const r5 = stream2Word(p, 16);
    strictEqual(r5, 0x6f726431, "Fifth word should be 0x6f726431");
  });
  test("encipher", () => {
    const p = Int32Array.from(P_ORIG);
    const s = Int32Array.from(S_ORIG);
    let lr = [0, 0];
    lr = encipher(lr, 0, p, s);
    strictEqual(lr[0], 1886232524, "First word should be 1886232524");
    strictEqual(lr[1], 395498042, "Second word should be 395498042");
    lr = encipher(lr, 0, p, s);
    strictEqual(lr[0], -36316569, "First word should be -36316569");
    strictEqual(lr[1], -1177159120, "Second word should be -2052912941");
  });
  test("ekskey", () => {
    const p = Uint8Array.from(Buffer.from(TEST_PASSWORD, "utf-8"));
    const s = Uint8Array.from(Buffer.from(TEST_SALT, "base64"));
    const P = Int32Array.from(P_ORIG);
    const S = Int32Array.from(S_ORIG);
    ekskey(p, s, P, S);
    strictEqual(Buffer.from(P).toString("base64"), "Th3Fn2HFdK4GaZ78PBJ57fcp");
    strictEqual(
      Buffer.from(S).toString("base64"),
      "7s+TgpUCi0ZHZIg8CV3yv5lwcgMOVA6jpgJY0/Bk8kUW4OAvVk6lbddbUJMMhCkWEgUQAYdJpgBl8ryIEPzrqO/ukiFttnrroUBrAlVP6mEhhS3ntGvZY3YPbKIkanPxOgvBKYuja9dmEAHzkq2GhSBd6IA3oODFMPx90gGJ3gN403YD0kQAcnakYlOIKT2OEgtYtQI25TwzoqYz5I7Usb5mX5yxwZx9aB+uMCMpNPie+DD1ymDVA+d0Nmqz/3q9+FlexGP0ml5mEbG6PguwJ92uYOjb6thmlElo9Meq5ZVd34NTQ+OR8dTKvnb8Ryfv2uPheVniI01zIdFqQSK0SE5pl/Mtv2ExAF2uXYf7snyvMsFke7DG9d5n7yfdJy9GzWsi4k2HwVOR7fhAhuYEmxNjZYODHE0LQtOp2LjYJaIgFtgHe/gJdoouqDDKeIapjBXU5wMczhCdNk4I3k4iLJ9F826oGlq7RwsQIetpuUuPEO2/4fE62Hv6IiwyQITcpPiKICtsm8iLlDdRyfBtBFQCZc++NzcRreDptcLkBgo2TE3oCw9V77w/napeR3d1LZr8AEM1ylsWDqhOgcRJt8sJANsySndNUsJfliTrEPoMML79JO01olVQLXsPW5AFIbL7ks3Nd0gD2GjBICcgQLt3XyWYewlbc0k6q5VubmNJaRI7T/wcZegVaorZl5MN/9tGXI1ZXiu7srT8mp13yZ7fCmfxthWrwtAcSFD2NOhSjtdJFDlewP2HT/h67V5XMml4Fkex9U9mlbVh3HkVjkMlRahB8FhzVtuojYlCR2rPVRrlN2woAQEnTIqUN0LY5F8/SU7bmNgPAEEZgl53mvweVAl89DwrHDm4LWDAvf4Vqnxu8lNSkWegyATVoHQmWpvrwmjMpWeXmHWWulxkzsgntiIqiK4/J4vXwIwHSusOpWC69hl24WeBFz24uPWd7D6nRyKA5ujlyqIAAkiEdyuL8F4lpCxQ7QKTSt+88FWicOIaR0agTKKM2gj8QLWjnS37UMUjmflvOsMuYeZSiRYpyNoydwX8DHuhx+p0VHfKk48LVTCxiKtbi3Gf9biqgjNPxAAgvhLp5xmFMv0yyX0fn9ULcVuplYjWNBbwSDfHENURWkVJ0jPOUKUhP6zgjGgZgLHDP1sGWSR8Np1Pn2n7HS+2474X/g6eKfEbXGMSugbG0Kk/nKZ/gC8oRSFzlzR5+XIhSnjpPao0Te7TgVz821GLYeIfsufj4hTgp7drKZC12uZidGTVhpwIIXFUSP3l0YLXDXS1JKMgZNDwJPTOLbCUBQ9ParprvieOS1itFK+c7Yd2F0GZXXX7Ziw3RZmMEipmGuHDFkYh9ZwJWw==",
    );
  });
  test("key", () => {
    const p = Uint8Array.from(Buffer.from(TEST_PASSWORD, "utf-8"));
    const P = Int32Array.from(P_ORIG);
    const S = Int32Array.from(S_ORIG);
    key(p, P, S);
    strictEqual(Buffer.from(P).toString("base64"), "dPbrzLh5SLkSv+6QF6TmhCzK");
    strictEqual(
      Buffer.from(S).toString("base64"),
      "NVoqXuZYeQ0zl5A7O75JrYZgFcyJ0n7bsgMUpQn/2I3/1j+pMK0w9iHGg7tvdbvOj2qnw2aHbZ+iKKkkck7T52gBnUQ+3kDx6MpOCVS2zYKNbq019XQ6riWQuCtbrNMhC2LCGiGxNzh/Th8hjWdW41Mjoqep45ZAYYaEnwOQsJqEIhLQ4Kjq6HhH4AzfpPFSPfhm6gsqESFmphWXJXG8qT3mbf6F+WrKA+HT+Z5N3OfnJsD/yg5v6zDotzAqcE0AbhvurkISo99+E1sjp6/Ec4ZJ3DeiNhAhE4L5GyykCHctjoDWVjsSPsovhfAyhWfez8CiLhg2z5JcH4IzPt2DXc03vBx6gzFX4GuETiMBGUyp3f4wIX48hCDhnE0vu3DB/HLUtlBgucPufRJ3nwvH0Q99eW3wOtotNgcvNxzonTKFbi5KLbFHpLehctLSwkYCpFts2YPZE+K3DVzYGmYcJ4rQIJ8YICV8Dfg3h2rS223HnX/bZSSIEijEhM+PfOKTo58+qwfISWBrF7KvWTGRy3Rq3/hK8Redw+G+qKr2cAefskTXHgRb9oLNUzKm/yubwVGjGdHn58z41DCOo6tCN4nmRFemOuwustrhPfiWV0ZqH+b3L1ATZVpOfktefG/5hVo81jo/9qZfe5Y4RGNvQPegJmkJ4Vnvj0ZPhW5XE3B95Unm38YxtvQ8o2pcHl391u6zLObMRpdQ/+U0RmA885dZ+faotIG0u4BK6CUrSlSxbh2Ok/6ylcZIONHOv7Bibaacjr40RfKraI3r3GVWBthvEZs+PKfG4MWEt3VPQFHr3L7wyz44gaeFlpJRiGxhJTqepM2dUtVCe4lOV35FPd/JmAcYVW5+fcBnluuAfHhsXYGS0r6629kEC4sbPlLbJRuDbaFS/nO4Sk1Wy4q4X+0ujmHgUEUrXDrI1W2bIL0TKW2051LC2jE5w+DtfdoAde6pGSYmmkDO1gQxjaB8UdahwjAYQ8oALn90R7GTw6uAy+qomrVR31qdOjQxgc3L+t0zCUtKRre0RVJYDbolkZwA6PXLyrQfhHnx6+XNa9iA5bI4C56wxgQu4o3Y3VLoBRTydunXzz2O/pSRfcYYC4f5P0BZDcimvGpb8j/XNAoAEGOIXOe/NWsunzOeKIAye03KuKoqsYaOkdQXQUVRt4LP+HcgnNByY0w0Gd+QKr1Rbl3+tybyuAVynQRmuzfXhkq/d3XokDjUrolRbqrsRG4ov34sEOkSc0hACdfzdVv++dr8xH3UPX+O+AByXM8jjX17Z7cjAoqW16yCLNQib7ah9LhoCVqo8r2ePm57awCodqIw+EzL7oTFyZYGYUKX4tSffqZcN7IyQo8MEl/Mjw==",
    );
  });
  test("crypt", () => {
    const p = Uint8Array.from(Buffer.from(TEST_PASSWORD, "utf-8"));
    const s = Uint8Array.from(Buffer.from(TEST_SALT, "base64"));
    const r = crypt(p, s, GENSALT_DEFAULT_LOG2_ROUNDS);
    strictEqual(
      Buffer.from(r).toString("base64"),
      "qQ+Q1AS67gbJxw8O1KfKKlo/0dGAf2hv",
    );
  });
  test("hash", () => {
    const h = hash(
      TEST_PASSWORD,
      GENSALT_DEFAULT_LOG2_ROUNDS,
      base642Base64BCrypt(TEST_SALT),
    );
    strictEqual(
      h,
      "$2a$10$R6297FEswqIxx9CmIQBZlOs6Xvuhbg2FpHBbzdwyOkrfTZRvSJ36m",
    );
  });
  test("verify", () => {
    const v = verify(
      TEST_PASSWORD,
      "$2a$10$R6297FEswqIxx9CmIQBZlOs6Xvuhbg2FpHBbzdwyOkrfTZRvSJ36m",
    );
    strictEqual(v, true);
  });
});

describe("bcrypt intergration test", () => {
  test("hash and verify", () => {
    const h = hash(TEST_PASSWORD);
    const v = verify(TEST_PASSWORD, h);
    strictEqual(v, true);
  });
});
