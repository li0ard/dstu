import { abytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import type { BlockMode, Cipher } from "../types.js";
import { abytesAligned, assertKalyna, xorBytes } from "../utils.js";

/** Cipher Block Chaining (CBC) mode */
export const cbc = (cipher: Cipher, iv: TArg<Uint8Array>): BlockMode => {
    assertKalyna(cipher);
    abytes(iv, cipher.blockSize, "iv");

    return Object.freeze({
        encrypt: (plaintext: TArg<Uint8Array>): TRet<Uint8Array> => {
            abytesAligned(plaintext, cipher.blockSize, "plaintext");
            let buf = iv;

            const output = new Uint8Array(plaintext.length);
            for(let i = 0; i < plaintext.length; i += cipher.blockSize) {
                const blk = cipher.encrypt(xorBytes(plaintext.subarray(i, i + cipher.blockSize), buf));
                output.set(blk, i);
                buf = blk;
            }

            return output;
        },
        decrypt: (ciphertext: TArg<Uint8Array>): TRet<Uint8Array> => {
            abytesAligned(ciphertext, cipher.blockSize, "ciphertext");
            let buf = iv;

            const output = new Uint8Array(ciphertext.length);
            for(let i = 0; i < ciphertext.length; i += cipher.blockSize) {
                const blk = ciphertext.subarray(i,i + cipher.blockSize);
                output.set(xorBytes(cipher.decrypt(blk), buf), i);
                buf = blk;
            }

            return output;
        }
    });
}