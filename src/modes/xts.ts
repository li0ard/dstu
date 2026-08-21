import { concatBytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import type { Kalyna } from "../kalyna/index.js";
import { gf2mMul, xorBytes } from "../utils.js";
import { numberToBytesLE } from "@noble/curves/utils.js";

/** XEX Tweakable Block Ciphertext Stealing (XTS) */
export const xts = (cipher: Kalyna): {
    encrypt: (plaintext: TArg<Uint8Array>, tweak: TArg<Uint8Array>) => TRet<Uint8Array>,
    decrypt: (ciphertext: TArg<Uint8Array>, iv: TArg<Uint8Array>) => TRet<Uint8Array>
} => {
    const two = numberToBytesLE(2, cipher.blockSize);
    const increaseGamma = (gamma: TArg<Uint8Array>): TRet<Uint8Array> =>
        gf2mMul(cipher.blockSize, gamma, two);

    const transform = (
        transform: (block: TArg<Uint8Array>) => TRet<Uint8Array>,
        block: TArg<Uint8Array>,
        gamma: TArg<Uint8Array>
    ): TRet<Uint8Array> => xorBytes(transform(xorBytes(block, gamma)), gamma);

    const init = (iv: TArg<Uint8Array>) => {
        const gamma = cipher.encrypt(iv); 
        const expanded = new Uint8Array(cipher.blockSize);
        expanded.set(gamma);

        return expanded;
    }

    return Object.freeze({
        encrypt: (plaintext: TArg<Uint8Array>, tweak: TArg<Uint8Array>): TRet<Uint8Array> => {
            if (plaintext.length < cipher.blockSize)
                throw new Error(`Invalid length (need at least ${cipher.blockSize}, got ${plaintext.length})`);

            let gamma = init(tweak);
            const encrypt = cipher.encrypt.bind(cipher)

            const buffer = new Uint8Array(plaintext);
            const k = Math.floor(plaintext.length / cipher.blockSize);
            const r = plaintext.length % cipher.blockSize;

            if (r === 0) {
                for (let off = 0; off < plaintext.length; off += cipher.blockSize) {
                    gamma = increaseGamma(gamma);
                    buffer.set(transform(encrypt, buffer.subarray(off, off + cipher.blockSize), gamma), off);
                }
            } else {
                for (let i = 0; i < k; i++) {
                    gamma = increaseGamma(gamma);
                    const off = i * cipher.blockSize;
                    buffer.set(transform(encrypt, buffer.subarray(off, off + cipher.blockSize), gamma), off);
                }

                const last_off = (k - 1) * cipher.blockSize;
                const tail_off = k * cipher.blockSize;
                const scratch = buffer.slice(last_off, last_off + cipher.blockSize);
                const combined = concatBytes(
                    buffer.subarray(tail_off, tail_off + r),
                    scratch.subarray(r)
                );

                gamma = increaseGamma(gamma);
                const encrypted = transform(encrypt, combined, gamma);

                buffer.set(encrypted, last_off);
                buffer.set(scratch.subarray(0, r), tail_off);
            }

            return buffer;
        },
        decrypt: (ciphertext: TArg<Uint8Array>, iv: TArg<Uint8Array>): TRet<Uint8Array> => {
            if (ciphertext.length < cipher.blockSize)
                throw new Error(`Invalid length (need at least ${cipher.blockSize}, got ${ciphertext.length})`);

            const n = ciphertext.length;

            let gamma = init(iv);
            const decrypt = cipher.decrypt.bind(cipher);

            const buffer = new Uint8Array(ciphertext);
            const k = Math.floor(n / cipher.blockSize);
            const r = n % cipher.blockSize;

            if (r === 0) {
                for (let off = 0; off < n; off += cipher.blockSize) {
                    gamma = increaseGamma(gamma);
                    buffer.set(transform(decrypt, buffer.subarray(off, off + cipher.blockSize), gamma), off);
                }
            } else {
                for (let i = 0; i < k - 1; i++) {
                    gamma = increaseGamma(gamma);
                    const off = i * cipher.blockSize;
                    buffer.set(transform(decrypt, buffer.subarray(off, off + cipher.blockSize), gamma), off);
                }

                gamma = increaseGamma(gamma);
                const gamma_k = gamma;
                const gamma_k_plus_1 = increaseGamma(gamma);

                const last_off = (k - 1) * cipher.blockSize;
                const tail_off = k * cipher.blockSize;
                const combined = transform(decrypt, buffer.subarray(last_off, last_off + cipher.blockSize), gamma_k_plus_1);

                const rec = concatBytes(
                    buffer.subarray(tail_off, tail_off + r),
                    combined.subarray(r)
                );
                const decrypted = transform(decrypt, rec, gamma_k);
 
                buffer.set(decrypted, last_off);
                buffer.set(combined.subarray(0, r), tail_off);
            }

            return buffer;
        }
    });
}