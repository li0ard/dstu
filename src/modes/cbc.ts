import type { TArg, TRet } from "@noble/hashes/utils.js";
import type { Kalyna } from "../kalyna/index.js";
import type { BlockMode } from "../types.js";
import { xorBytes } from "../utils.js";

/** Cipher Block Chaining (CBC) mode */
export const cbc = (cipher: Kalyna, iv: TArg<Uint8Array>): BlockMode => {
    if (iv.length !== cipher.blockSize) throw new Error("Invalid IV size");

    return Object.freeze({
        encrypt: (plaintext: TArg<Uint8Array>): TRet<Uint8Array> => {
            if (plaintext.length % cipher.blockSize !== 0) throw new Error("Plaintext not aligned");
            let buf: TArg<Uint8Array> = new Uint8Array(iv);

            const output = new Uint8Array(plaintext.length);
            for(let i = 0; i < plaintext.length; i += cipher.blockSize) {
                const blk = cipher.encrypt(xorBytes(plaintext.subarray(i, i + cipher.blockSize), buf));
                output.set(blk, i);
                buf = blk.slice();
            }

            return output;
        },
        decrypt: (ciphertext: TArg<Uint8Array>): TRet<Uint8Array> => {
            if (ciphertext.length % cipher.blockSize !== 0) throw new Error("Ciphertext not aligned");
            let buf: TArg<Uint8Array> = new Uint8Array(iv);

            const output = new Uint8Array(ciphertext.length);
            for(let i = 0; i < ciphertext.length; i += cipher.blockSize) {
                const blk = ciphertext.subarray(i,i + cipher.blockSize);
                output.set(xorBytes(cipher.decrypt(blk), buf), i);
                buf = blk.slice();
            }

            return output;
        }
    });
}