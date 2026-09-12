import { numberToBytesLE, concatBytes, type TArg, type TRet } from "@noble/curves/utils.js";
import { assertKalyna, gf2mMul } from "../utils.js";
import type { Cipher, GMACMode } from "../types.js";

const xorBytesInPlace = (a: TArg<Uint8Array>, b: TArg<Uint8Array>) => {
    if(a.length != b.length) throw new Error("Byte arrays must have same length");
    for(let i = 0; i < a.length; i++) a[i] ^= b[i];
}
/** Galois Message Authentication Code (GMAC) mode */
export const gmac = (cipher: Cipher, q = 16): GMACMode => {
    assertKalyna(cipher);
    const hblock = cipher.blockSize >> 1;

    return Object.freeze({
        compute: (msg: TArg<Uint8Array>, aad?: TArg<Uint8Array>): TRet<Uint8Array> => {
            aad ??= new Uint8Array();
            const H = cipher.encrypt(new Uint8Array(cipher.blockSize));

            const B = new Uint8Array(cipher.blockSize);
            const updateMac = (input: TArg<Uint8Array>) => {
                let i = 0;
                while(i < input.length) {
                    const blockSizeToProcess = Math.min(cipher.blockSize, input.length - i);
                    const block = new Uint8Array(cipher.blockSize);
                    for (let j = 0; j < blockSizeToProcess; j++) block[j] = input[i + j];
                    if (blockSizeToProcess < cipher.blockSize) block[blockSizeToProcess] = 0x80;
                    for (let j = 0; j < cipher.blockSize; j++) B[j] ^= block[j];
                    B.set(gf2mMul(cipher.blockSize, B, H));
        
                    i += cipher.blockSize;
                }
            }
            updateMac(aad);
            updateMac(msg);

            xorBytesInPlace(B, concatBytes(
                numberToBytesLE(aad.length * 8, hblock),
                numberToBytesLE(msg.length * 8, hblock)
            ));

            return cipher.encrypt(B).slice(0, q);
        }
    });
}