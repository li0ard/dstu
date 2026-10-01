import { abytes, copyBytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import type { BlockMode, Cipher } from "../types.js";
import { isKalyna, xorBytes } from "../utils.js";

/** Cipher Feedback (CFB) mode */
export const cfb = (cipher: Cipher, iv: TArg<Uint8Array>, q: number = cipher.blockSize): BlockMode => {
    const _isKalyna = isKalyna(cipher);
    if(_isKalyna && q !== 1 && q !== 8 && q !== 16 && q !== 32 && q !== 64) throw new Error('q must be 1, 8, 16, 32, or 64');
    if(_isKalyna && q > cipher.blockSize) throw new Error('q cannot exceed block size');
    abytes(iv)
    if(iv.length === 0 || iv.length % cipher.blockSize !== 0) throw new Error("Invalid IV size");

    if(_isKalyna) return Object.freeze({
        encrypt: (plaintext: TArg<Uint8Array>): TRet<Uint8Array> => {
            abytes(plaintext);
            const gamma = cipher.encrypt(iv);
            const feed = copyBytes(iv);
            const result = new Uint8Array(plaintext.length);

            let offset = 0;
            while (offset + q <= plaintext.length) {
                for (let i = 0; i < q; i++)
                    result[offset + i] = plaintext[offset + i] ^ gamma[cipher.blockSize - q + i];
                feed.set(gamma.subarray(0, cipher.blockSize - q));
                feed.set(result.subarray(offset, offset + q), cipher.blockSize - q);
                gamma.set(cipher.encrypt(feed));
                offset += q;
            }

            while (offset < plaintext.length) {
                result[offset] = plaintext[offset] ^ gamma[cipher.blockSize - (plaintext.length - offset)];
                offset++;
            }

            return result;
        },
        decrypt: (ciphertext: TArg<Uint8Array>): TRet<Uint8Array> => {
            abytes(ciphertext);
            const gamma = cipher.encrypt(iv);
            const feed = copyBytes(iv);
            const result = new Uint8Array(ciphertext.length);

            let offset = 0;
            while (offset + q <= ciphertext.length) {
                for (let i = 0; i < q; i++)
                    result[offset + i] = ciphertext[offset + i] ^ gamma[cipher.blockSize - q + i];
                feed.set(gamma.subarray(0, cipher.blockSize - q));
                feed.set(ciphertext.subarray(offset, offset + q), cipher.blockSize - q);
                gamma.set(cipher.encrypt(feed));
                offset += q;
            }

            while (offset < ciphertext.length) {
                result[offset] = ciphertext[offset] ^ gamma[cipher.blockSize - (ciphertext.length - offset)];
                offset++;
            }

            return result;
        }
    });
    else return Object.freeze({
        encrypt: (plaintext: TArg<Uint8Array>): TRet<Uint8Array> => {
            abytes(plaintext);
            const r: Uint8Array[] = [];
            for (let i = 0; i < iv.length; i += cipher.blockSize)
                r.push(iv.subarray(i, i + cipher.blockSize));

            const out = new Uint8Array(plaintext.length);
            for (let n = 0; n < Math.ceil(plaintext.length / cipher.blockSize); n++) {
                const i = n * cipher.blockSize;
                const ct = xorBytes(plaintext.subarray(i, i + cipher.blockSize), cipher.encrypt(r[0]));
                out.set(ct, i);
                r.shift();
                r.push(ct);
            }

            return out;
        },
        decrypt: (ciphertext: TArg<Uint8Array>): TRet<Uint8Array> => {
            abytes(ciphertext);
            const r: Uint8Array[] = [];
            for (let i = 0; i < iv.length; i += cipher.blockSize)
                r.push(iv.subarray(i, i + cipher.blockSize));

            const out = new Uint8Array(ciphertext.length);
            for (let n = 0; n < Math.ceil(ciphertext.length / cipher.blockSize); n++) {
                const i = n * cipher.blockSize;
                const blk = ciphertext.subarray(i, i + cipher.blockSize);
                out.set(xorBytes(blk, cipher.encrypt(r[0])), i);
                r.shift();
                r.push(blk);
            }

            return out;
        }
    });
}