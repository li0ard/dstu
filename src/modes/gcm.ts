import { concatBytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import type { Kalyna } from "../kalyna/index.js";
import { ctr } from "./ctr.js";
import { gmac } from "./mac.js";
import { equalBytes } from "../utils.js";
import type { AEADMode } from "../types.js";

/** Galois counter (GCM) mode (AEAD) */
export const gcm = (cipher: Kalyna, iv: TArg<Uint8Array>, q = 16): AEADMode => {
    return {
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
    }
}