import { concatBytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import { ctr } from "./ctr.js";
import { gmac } from "./gmac.js";
import type { AEADMode, Cipher } from "../types.js";
import { equalBytes } from "@noble/curves/utils.js";

/** Galois counter (GCM) mode (AEAD) */
export const gcm = (cipher: Cipher, iv: TArg<Uint8Array>, q = 16): AEADMode => Object.freeze({
    seal: (plaintext: TArg<Uint8Array>, aad?: TArg<Uint8Array>): TRet<Uint8Array> => {
        const enc = ctr(cipher, iv).crypt(plaintext);
        return concatBytes(enc, gmac(cipher, q).compute(aad || new Uint8Array(), enc));
    },
    open: (ciphertext: TArg<Uint8Array>, aad?: TArg<Uint8Array>): TRet<Uint8Array> => {
        const enc = ciphertext.subarray(0, -q);
        const hC = gmac(cipher, q).compute(aad || new Uint8Array(), enc);
        if(!equalBytes(ciphertext.subarray(-q), hC))
            throw new Error("Invalid MAC");

        return ctr(cipher, iv).crypt(enc);
    }
});