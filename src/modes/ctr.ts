import { createView, type TArg, type TRet } from "@noble/hashes/utils.js";
import { isKalyna, xorBytes } from "../utils.js";
import type { Cipher, StreamMode } from "../types.js";

const C1 = 0x01010104, C2 = 0x01010101;

/** Counter (CTR) mode */
export const ctr = (cipher: Cipher, iv: TArg<Uint8Array>): StreamMode => {
    if (iv.length !== cipher.blockSize) throw new Error("Invalid IV size");

    const incrementCounter = (ctr: TArg<Uint8Array>) => {
        if(isKalyna(cipher)) {
            let j = 0;
            while (j < ctr.length) if (++ctr[j++] != 0) break;
        } else {
            const view = createView(ctr);
            view.setUint32(0, (view.getUint32(0, true) + C2) >>> 0, true);
            let s2 = view.getUint32(4, true) + C1;
            if (s2 >= 0xFFFFFFFF) s2 -= 0xFFFFFFFF;
            view.setUint32(4, s2 >>> 0, true);
        }
    }

    return Object.freeze({
        crypt: (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
            const buf = cipher.encrypt(iv),
                output = new Uint8Array(msg.length);
            for (let i = 0; i < msg.length; i += cipher.blockSize) {
                incrementCounter(buf);
                const ct = xorBytes(cipher.encrypt(buf), msg.subarray(i, i + cipher.blockSize));
                output.set(ct, i);
            }

            return output;
        }
    });
}