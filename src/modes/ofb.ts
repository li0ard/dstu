import { type TArg, type TRet } from "@noble/hashes/utils.js";
import type { Kalyna } from "../kalyna/index.js";
import type { StreamMode } from "../types.js";
import { xorBytes } from "../utils.js";

/** Output Feedback (OFB) mode */
export const ofb = (cipher: Kalyna, iv: TArg<Uint8Array>): StreamMode => {
    if (iv.length !== cipher.blockSize) throw new Error("Invalid IV size");

    return Object.freeze({
        crypt: (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
            let buf = new Uint8Array(iv);
            const output = new Uint8Array(msg.length);
            for (let i = 0; i < msg.length; i += cipher.blockSize) {
                const enc = cipher.encrypt(buf);
                output.set(xorBytes(enc, msg.subarray(i, i + cipher.blockSize)), i);
                buf = enc;
            }

            return output;
        }
    });
}