import { abytes, concatBytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import { assertKalyna, xorBytes } from "../utils.js";
import type { Cipher, DiskMode } from "../types.js";
import { gf2mDouble } from "../gf/index.js";

/** XEX Tweakable Block Ciphertext Stealing (XTS) */
export const xts = (cipher: Cipher): DiskMode => {
    assertKalyna(cipher);

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
            abytes(plaintext, undefined, "plaintext");
            abytes(tweak, undefined, "tweak");
            if (plaintext.length < cipher.blockSize)
                throw new Error(`Invalid length (need at least ${cipher.blockSize}, got ${plaintext.length})`);

            const gamma = init(tweak);
            const encrypt = cipher.encrypt.bind(cipher)

            const buffer = new Uint8Array(plaintext);
            const k = Math.floor(plaintext.length / cipher.blockSize);
            const r = plaintext.length % cipher.blockSize;

            if (r === 0) {
                for (let off = 0; off < plaintext.length; off += cipher.blockSize) {
                    gamma.set(gf2mDouble(cipher.blockSize, gamma));
                    buffer.set(transform(encrypt, buffer.subarray(off, off + cipher.blockSize), gamma), off);
                }
            } else {
                for (let i = 0; i < k; i++) {
                    gamma.set(gf2mDouble(cipher.blockSize, gamma));
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

                const encrypted = transform(encrypt, combined, gf2mDouble(cipher.blockSize, gamma));
                buffer.set(encrypted, last_off);
                buffer.set(scratch.subarray(0, r), tail_off);
            }

            return buffer;
        },
        decrypt: (ciphertext: TArg<Uint8Array>, tweak: TArg<Uint8Array>): TRet<Uint8Array> => {
            abytes(ciphertext, undefined, "ciphertext");
            abytes(tweak, undefined, "tweak");
            if (ciphertext.length < cipher.blockSize)
                throw new Error(`Invalid length (need at least ${cipher.blockSize}, got ${ciphertext.length})`);

            const gamma = init(tweak);
            const decrypt = cipher.decrypt.bind(cipher);

            const buffer = new Uint8Array(ciphertext);
            const k = Math.floor(ciphertext.length / cipher.blockSize);
            const r = ciphertext.length % cipher.blockSize;

            if (r === 0) {
                for (let off = 0; off < ciphertext.length; off += cipher.blockSize) {
                    gamma.set(gf2mDouble(cipher.blockSize, gamma));
                    buffer.set(transform(decrypt, buffer.subarray(off, off + cipher.blockSize), gamma), off);
                }
            } else {
                for (let i = 0; i < k - 1; i++) {
                    gamma.set(gf2mDouble(cipher.blockSize, gamma));
                    const off = i * cipher.blockSize;
                    buffer.set(transform(decrypt, buffer.subarray(off, off + cipher.blockSize), gamma), off);
                }

                gamma.set(gf2mDouble(cipher.blockSize, gamma));
                const gamma_k_plus_1 = gf2mDouble(cipher.blockSize, gamma);

                const last_off = (k - 1) * cipher.blockSize;
                const tail_off = k * cipher.blockSize;
                const combined = transform(decrypt, buffer.subarray(last_off, last_off + cipher.blockSize), gamma_k_plus_1);

                const rec = concatBytes(
                    buffer.subarray(tail_off, tail_off + r),
                    combined.subarray(r)
                );
                const decrypted = transform(decrypt, rec, gamma);
 
                buffer.set(decrypted, last_off);
                buffer.set(combined.subarray(0, r), tail_off);
            }

            return buffer;
        }
    });
}