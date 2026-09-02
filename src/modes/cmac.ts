import { copyBytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import type { Kalyna } from "../kalyna/index.js";
import type { MACMode } from "../types.js";
import { pad } from "../padding.js";
import { xorBytes } from "../utils.js";

export const cmac = (cipher: Kalyna, q = 16): MACMode => Object.freeze({
    compute: (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
        let data = copyBytes(msg);
        const zeroBlock = new Uint8Array(cipher.blockSize);
        if(data.length % cipher.blockSize !== 0) {
            data = pad(data, cipher.blockSize);
            zeroBlock[0] = 1;
        }

        const Kd = cipher.encrypt(zeroBlock);
        const c = new Uint8Array(cipher.blockSize);
        const numBlocks = data.length / cipher.blockSize;
        for (let i = 0; i < numBlocks - 1; i++) {
            const blockStart = i * cipher.blockSize;        
            c.set(cipher.encrypt(xorBytes(c, data.subarray(blockStart, blockStart + cipher.blockSize))));
        }

        const lastBlockStart = (numBlocks - 1) * cipher.blockSize;
        c.set(cipher.encrypt(xorBytes(xorBytes(c, data.subarray(lastBlockStart, lastBlockStart + cipher.blockSize)), Kd)));

        return c.slice(0, q);
    }
});