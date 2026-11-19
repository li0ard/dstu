import { abytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import type { Cipher, StreamMode } from "../types.js";
import { xorBytes } from "../utils.js";
import { assertKalyna } from "./_guard.js";

/** Output Feedback (OFB) mode */
export const ofb = (cipher: Cipher, iv: TArg<Uint8Array>): StreamMode => {
    assertKalyna(cipher);
    abytes(iv, cipher.blockSize, "iv");

    return Object.freeze({
        crypt: (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
            abytes(msg, undefined, "msg");
            let buf = iv;
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