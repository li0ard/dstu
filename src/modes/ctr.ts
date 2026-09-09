import { concatBytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import { xorBytes } from "../utils.js";
import type { Cipher, StreamMode } from "../types.js";

const incrementCounterAt = (ctr: TArg<Uint8Array>, pos: number) => {
    let j = pos;
    while (j < ctr.length) if (++ctr[j++] != 0) break;
}

/** Counter (CTR) mode */
export const ctr = (cipher: Cipher, iv: TArg<Uint8Array>): StreamMode => {
    if (iv.length !== cipher.blockSize) throw new Error("Invalid IV size");

    return Object.freeze({
        crypt: (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
            const buf = cipher.encrypt(iv),
                output = new Uint8Array(msg.length);
            for (let i = 0; i < msg.length; i += cipher.blockSize) {
                incrementCounterAt(buf, 0);
                const ct = xorBytes(cipher.encrypt(buf), msg.subarray(i, i + cipher.blockSize));
                output.set(ct, i);
            }

            return output;
        }
    });
}