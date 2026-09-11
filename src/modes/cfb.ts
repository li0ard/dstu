import { concatBytes, copyBytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import type { BlockMode, Cipher } from "../types.js";
import { isKalyna, xorBytes } from "../utils.js";

/** Cipher Feedback (CFB) mode */
export const cfb = (cipher: Cipher, iv: TArg<Uint8Array>, q: number = cipher.blockSize): BlockMode => {
    const _isKalyna = isKalyna(cipher);
    if(_isKalyna && q !== 1 && q !== 8 && q !== 16 && q !== 32 && q !== 64) throw new Error('q must be 1, 8, 16, 32, or 64');
    if(_isKalyna && q > cipher.blockSize) throw new Error('q cannot exceed block size');
    if(!_isKalyna && (iv.length === 0 || iv.length % cipher.blockSize !== 0)) throw new Error("Invalid IV size");

    if(_isKalyna) return Object.freeze({
        encrypt: (plaintext: TArg<Uint8Array>): TRet<Uint8Array> => {
            const gamma = cipher.encrypt(iv);
            const feed = copyBytes(iv);
            const result = new Uint8Array(plaintext.length);

            let offset = 0, dataOff = 0;
            while (offset > 0 && dataOff < plaintext.length) {
                result[dataOff] = plaintext[dataOff] ^ gamma[offset];
                feed[offset++] = result[dataOff++];
                if (offset >= cipher.blockSize) {
                    gamma.set(cipher.encrypt(feed));
                    offset = cipher.blockSize - q;
                }
            }

            while (dataOff + q <= plaintext.length) {
                for (let i = 0; i < q; i++)
                    result[dataOff + i] = plaintext[dataOff + i] ^ gamma[cipher.blockSize - q + i];
                feed.set(gamma.subarray(0, cipher.blockSize - q));
                feed.set(result.subarray(dataOff, dataOff + q), cipher.blockSize - q);
                gamma.set(cipher.encrypt(feed));
                dataOff += q;
            }

            while (dataOff < plaintext.length) {
                result[dataOff] = plaintext[dataOff] ^ gamma[cipher.blockSize - (plaintext.length - dataOff)];
                dataOff++;
            }

            return result;
        },
        decrypt: (ciphertext: TArg<Uint8Array>): TRet<Uint8Array> => {
            const gamma = cipher.encrypt(iv);
            const feed = copyBytes(iv);
            const result = new Uint8Array(ciphertext.length);

            let offset = 0, dataOff = 0;
            while (offset > 0 && dataOff < ciphertext.length) {
                result[dataOff] = ciphertext[dataOff] ^ gamma[offset];
                feed[offset++] = ciphertext[dataOff++];
                if (offset >= cipher.blockSize) {
                    gamma.set(cipher.encrypt(feed));
                    offset = cipher.blockSize - q;
                }
            }

            while (dataOff + q <= ciphertext.length) {
                for (let i = 0; i < q; i++)
                    result[dataOff + i] = ciphertext[dataOff + i] ^ gamma[cipher.blockSize - q + i];
                feed.set(gamma.subarray(0, cipher.blockSize - q));
                feed.set(ciphertext.subarray(dataOff, dataOff + q), cipher.blockSize - q);
                gamma.set(cipher.encrypt(feed));
                dataOff += q;
            }

            while (dataOff < ciphertext.length) {
                result[dataOff] = ciphertext[dataOff] ^ gamma[cipher.blockSize - (ciphertext.length - dataOff)];
                dataOff++;
            }

            return result;
        }
    });
    else return Object.freeze({
        encrypt: (plaintext: TArg<Uint8Array>): TRet<Uint8Array> => {
            let r: Uint8Array[] = [];
            for (let i = 0; i < iv.length; i += cipher.blockSize)
                r.push(iv.subarray(i, i + cipher.blockSize));

            const len = Math.max(8, (plaintext.length + 7) & ~7);
            const result: Uint8Array[] = [];
            for(let i = 0; i < len; i += cipher.blockSize) {
                result.push(xorBytes(cipher.encrypt(r[0]), plaintext.subarray(i, i + cipher.blockSize)));
                r = r.slice(1).concat(result[result.length - 1]);
            }

            return concatBytes(...result);
        },
        decrypt: (ciphertext: TArg<Uint8Array>): TRet<Uint8Array> => {
            let r: Uint8Array[] = [];
            for (let i = 0; i < iv.length; i += cipher.blockSize)
                r.push(iv.subarray(i, i + cipher.blockSize));

            const len = Math.max(8, (ciphertext.length + 7) & ~7);
            const result: Uint8Array[] = [];
            for(let i = 0; i < len; i += cipher.blockSize) {
                const blk = ciphertext.slice(i, i + cipher.blockSize);
                result.push(xorBytes(cipher.encrypt(r[0]), blk));
                r = r.slice(1).concat(blk);
            }

            return concatBytes(...result);
        }
    });
}