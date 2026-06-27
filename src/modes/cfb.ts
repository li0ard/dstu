import type { TArg, TRet } from "@noble/hashes/utils.js";
import type { Kalyna } from "../kalyna/index.js";
import type { BlockMode } from "../types.js";

/** Cipher Feedback (CFB) mode */
export const cfb = (cipher: Kalyna, iv: TArg<Uint8Array>, q: number = cipher.blockSize): BlockMode => {
    const encrypter = cipher.encrypt.bind(cipher);

    return {
        encrypt: (plaintext: TArg<Uint8Array>): TRet<Uint8Array> => {
            const blockSize = cipher.blockSize;
            if (q !== 1 && q !== 8 && q !== 16 && q !== 32 && q !== 64) throw new Error('q must be 1, 8, 16, 32, or 64');
            if (q > blockSize) throw new Error('q cannot exceed block size');

            let gamma = encrypter(iv);
            const feed = new Uint8Array(iv);
            let offset = 0;
            const result = new Uint8Array(plaintext.length);
            let dataOff = 0;

            while (offset > 0 && dataOff < plaintext.length) {
                result[dataOff] = plaintext[dataOff] ^ gamma[offset];
                feed[offset++] = result[dataOff++];
        
                if (offset >= blockSize) {
                    gamma = encrypter(feed);
                    offset = blockSize - q;
                }
            }

            while (dataOff + q <= plaintext.length) {
                for (let i = 0; i < q; i++) result[dataOff + i] = plaintext[dataOff + i] ^ gamma[blockSize - q + i];
                feed.set(gamma.subarray(0, blockSize - q));
                feed.set(result.subarray(dataOff, dataOff + q), blockSize - q);
        
                gamma = encrypter(feed);
                dataOff += q;
            }

            while (dataOff < plaintext.length) {
                result[dataOff] = plaintext[dataOff] ^ gamma[blockSize - (plaintext.length - dataOff)];
                dataOff++;
            }

            return result;
        },

        decrypt: (ciphertext: TArg<Uint8Array>): TRet<Uint8Array> => {
            const blockSize = cipher.blockSize;
            if (q !== 1 && q !== 8 && q !== 16 && q !== 32 && q !== 64) throw new Error('q must be 1, 8, 16, 32, or 64');
            if (q > blockSize) throw new Error('q cannot exceed block size');

            let gamma = encrypter(iv);
            const feed = new Uint8Array(iv);
            let offset = 0;
            const result = new Uint8Array(ciphertext.length);
            let dataOff = 0;

            while (offset > 0 && dataOff < ciphertext.length) {
                result[dataOff] = ciphertext[dataOff] ^ gamma[offset];
                feed[offset++] = ciphertext[dataOff++];
        
                if (offset >= blockSize) {
                    gamma = encrypter(feed);
                    offset = blockSize - q;
                }
            }

            while (dataOff + q <= ciphertext.length) {
                for (let i = 0; i < q; i++) result[dataOff + i] = ciphertext[dataOff + i] ^ gamma[blockSize - q + i];
                feed.set(gamma.subarray(0, blockSize - q));
                feed.set(ciphertext.subarray(dataOff, dataOff + q), blockSize - q);
        
                gamma = encrypter(feed);
                dataOff += q;
            }

            while (dataOff < ciphertext.length) {
                result[dataOff] = ciphertext[dataOff] ^ gamma[blockSize - (ciphertext.length - dataOff)];
                dataOff++;
            }

            return result;
        }
    }
}