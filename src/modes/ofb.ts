import { type TArg, type TRet } from "@noble/hashes/utils.js";
import type { Kalyna } from "../kalyna/index.js";
import { ofb as ofb_ } from "@li0ard/sp80038";
import type { StreamMode } from "../types.js";

/** Output Feedback (OFB) mode */
export const ofb = (cipher: Kalyna, iv: TArg<Uint8Array>): StreamMode => {
    if (iv.length !== cipher.blockSize) throw new Error("Invalid IV size");
    const encrypter = cipher.encrypt.bind(cipher)

    return {
        crypt: (msg: TArg<Uint8Array>): TRet<Uint8Array> => ofb_(encrypter, cipher.blockSize, msg, iv)
    }
}