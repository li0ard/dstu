import { concatBytes, type TArg, type TRet, bytesToNumberLE, numberToBytesLE } from "@noble/curves/utils.js";
import type { Cipher, MACMode } from "../types.js";
import { pad } from "../padding.js";
import { isKalyna, xorBytes } from "../utils.js";
import { keySequences } from "../dstu9311/const.js";
import type { Dstu9311 } from "../dstu9311/index.js";

export const cmac = (cipher: Cipher, q = 16): MACMode => {
    if(isKalyna(cipher)) return Object.freeze({
        compute: (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
            let data = msg;
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
    else return Object.freeze({
        compute: (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
            const paddedLength = Math.max(8, (msg.length + 7) & ~7);
            const paddedData = new Uint8Array(paddedLength);
            paddedData.set(msg);

            let prev0 = 0n, prev1 = 0n;
            const feedback = new Uint8Array(cipher.blockSize);
            for (let i = 0; i < paddedData.length; i += cipher.blockSize) {
                feedback.set(numberToBytesLE(prev1, 4), 0);
                feedback.set(numberToBytesLE(prev0, 4), 4);

                const out = (cipher as Dstu9311).proceedBlock(
                    xorBytes(paddedData.subarray(i, i + cipher.blockSize), feedback),
                    keySequences.MAC
                );

                prev0 = bytesToNumberLE(out.subarray(0, 4));
                prev1 = bytesToNumberLE(out.subarray(4, 8));
            }

            return concatBytes(numberToBytesLE(prev1, 4), numberToBytesLE(prev0, 4)).slice(0, q);
        }
    });
}