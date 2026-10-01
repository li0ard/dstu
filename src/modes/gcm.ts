import { equalBytes, concatBytes, type TArg, type TRet } from "@noble/curves/utils.js";
import { gmac } from "./gmac.js";
import type { AEADMode, Cipher } from "../types.js";
import { assertKalyna, xorBytes } from "../utils.js";
import { abytes } from "@noble/hashes/utils.js";

// CTR for GCM and CCM
export const half_ctr = (cipher: Cipher, iv: TArg<Uint8Array>) => {
    abytes(iv, cipher.blockSize, "iv");
    return Object.freeze({
        crypt: (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
            abytes(msg);
            const buf = cipher.encrypt(iv),
                output = new Uint8Array(msg.length),
                half_len_word = cipher.blockSize >> 1;
        
            for (let i = 0; i < msg.length; i += cipher.blockSize) {
                for (let j = 0; j < half_len_word; j++) {
                    if (++buf[j] != 0) break;
                }
                const ct = xorBytes(cipher.encrypt(buf), msg.subarray(i, i + cipher.blockSize));
                output.set(ct, i);
            }

            return output;
        }
    });
}

/** Galois counter (GCM) mode (AEAD) */
export const gcm = (cipher: Cipher, iv: TArg<Uint8Array>, q = 16): AEADMode => {
    assertKalyna(cipher);
    abytes(iv, cipher.blockSize, "iv");

    const mode = half_ctr(cipher, iv);

    return Object.freeze({
        seal: (plaintext: TArg<Uint8Array>, aad?: TArg<Uint8Array>): TRet<Uint8Array> => {
            abytes(plaintext);
            if(aad) abytes(aad);
            const enc = mode.crypt(plaintext);
            return concatBytes(enc, gmac(cipher, q).compute(enc, aad));
        },
        open: (ciphertext: TArg<Uint8Array>, aad?: TArg<Uint8Array>): TRet<Uint8Array> => {
            abytes(ciphertext);
            if(aad) abytes(aad);
            const enc = ciphertext.subarray(0, -q);
            const hC = gmac(cipher, q).compute(enc, aad);
            if(!equalBytes(ciphertext.subarray(-q), hC))
                throw new Error("Invalid MAC");

            return mode.crypt(enc);
        }
    });
}