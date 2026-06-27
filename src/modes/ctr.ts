import { concatBytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import type { Kalyna } from "../kalyna/index.js";
import { xorBytes } from "../utils.js";
import type { StreamMode } from "../types.js";

const incrementCounterAt = (ctr: TArg<Uint8Array>, pos: number) => {
    let j = pos;
    while (j < ctr.length) if (++ctr[j++] != 0) break;
}

/** Counter (CTR) mode */
export const ctr = (cipher: Kalyna, iv: TArg<Uint8Array>): StreamMode => {
    if (iv.length !== cipher.blockSize) throw new Error("Invalid IV size");

    return {
        crypt: (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
            const keystreamBlocks: Uint8Array[] = [];
            const ctr = cipher.encrypt(iv);
            for (let i = 0; i < Math.ceil(msg.length / cipher.blockSize); i++) {
                incrementCounterAt(ctr, 0);
                keystreamBlocks.push(cipher.encrypt(ctr));
            }

            return xorBytes(concatBytes(...keystreamBlocks), msg);
        }
    }
}