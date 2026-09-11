import { equalBytes, concatBytes, type TArg, type TRet } from "@noble/curves/utils.js";
import type { AEADMode, Cipher } from "../types.js";
import { assertKalyna } from "../utils.js";
import { pad } from "../padding.js";
import { ctr } from "./ctr.js";

/** Counter with CBC-MAC (CCM) mode (AEAD) */
export const ccm = (cipher: Cipher, iv: TArg<Uint8Array>, q = 16, Nb = 4): AEADMode => {
    assertKalyna(cipher);
    if(q !== 8 && q !== 16 && q !== 32 && q !== 48 && q !== 64) throw new Error('q must be 8, 16, 32, 48, or 64');
    if (cipher.blockSize < Nb + 1) throw new Error('Cipher block size must be >= Nb + 1');
    const tmp = cipher.blockSize - 1, tmp2 = tmp - Nb;

    const calculateMac = (msg: TArg<Uint8Array>, aad?: TArg<Uint8Array>) => {
        aad ??= new Uint8Array();
        const G1 = new Uint8Array(cipher.blockSize),
            G2 = new Uint8Array(cipher.blockSize),
            B = new Uint8Array(cipher.blockSize);
        G1.set(iv.subarray(0, tmp2));
        G1[tmp2] = msg.length & 0xFF;
        G1[tmp] = (msg.length > 0 ? 128 : 0) | (q + 32 - (q % 16)) | (Nb - 1);
        G2[0] = aad.length & 0xFF;

        const updateMac = (data: TArg<Uint8Array>) => {
            for (let i = 0; i < data.length; i += cipher.blockSize) {
                const chunk = data.subarray(i, i + cipher.blockSize);
                for (let j = 0; j < cipher.blockSize; j++) B[j] ^= chunk[j];
                B.set(cipher.encrypt(B));
            }
        }

        updateMac(concatBytes(G1, G2.subarray(0, cipher.blockSize - (aad.length % cipher.blockSize)), aad));
        updateMac(pad(msg, cipher.blockSize));

        return B.slice(0, q);
    }

    const mode = ctr(cipher, iv);

    return Object.freeze({
        seal: (plaintext: TArg<Uint8Array>, aad?: TArg<Uint8Array>): TRet<Uint8Array> => {
            const mac = calculateMac(plaintext, aad);
            return mode.crypt(concatBytes(plaintext, mac));
        },
        open: (ciphertext: TArg<Uint8Array>, aad?: TArg<Uint8Array>): TRet<Uint8Array> => {
            const decrypted = mode.crypt(ciphertext);
            const plaintext = decrypted.slice(0, -q);
            const hC = calculateMac(plaintext, aad);
            if(!equalBytes(decrypted.subarray(-q), hC))
                throw new Error("Invalid MAC");

            return plaintext;
        }
    });
}