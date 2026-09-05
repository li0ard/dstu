import { concatBytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import { pad, unpad } from "../padding.js";
import type { Cipher } from "../types.js";

/** Key wrapping (KW) */
export const kw = (cipher: Cipher): {
    wrap: (key: TArg<Uint8Array>) => TRet<Uint8Array>,
    unwrap: (wrappedKey: TArg<Uint8Array>) => TRet<Uint8Array>,
} => {
    const half = cipher.blockSize >> 1;

    return Object.freeze({
        wrap: (key: TArg<Uint8Array>): TRet<Uint8Array> => {
            let plaintext;
            if (key.length % cipher.blockSize === 0) plaintext = key;
            else {
                const withLength = new Uint8Array(key.length + half);
                withLength.set(key);

                let bitLength = key.length << 3;
                let i = 0;
                while (bitLength > 0) {
                    withLength[key.length + i] = bitLength & 0xff;
                    i++;
                    bitLength >>>= 8;
                }

                plaintext = pad(withLength, cipher.blockSize);
            }

            const r = plaintext.length / cipher.blockSize;
            const n = 2 * (r + 1);
            const v = (n - 1) * 6;
            const qLen = (n - 1) * half;

            const B = plaintext.slice(0, half);
            const q = new Uint8Array(qLen);
            q.set(plaintext.subarray(half));

            const block = new Uint8Array(cipher.blockSize);
            for (let i = 1; i <= v; i++) {
                block.set(B);
                block.set(q.subarray(0, half), half);
                const encrypted = cipher.encrypt(block);

                q.copyWithin(0, half);
                q.set(encrypted.subarray(0, half), qLen - half);

                B.set(encrypted.subarray(half));
                B[0] ^= i & 0xff;
                B[1] ^= (i >>> 8) & 0xff;
                B[2] ^= (i >>> 16) & 0xff;
                B[3] ^= (i >>> 24) & 0xff;
            }

            return concatBytes(B,q);
        },
        unwrap: (wrappedKey: TArg<Uint8Array>): TRet<Uint8Array> => {
            if (wrappedKey.length < 2 * cipher.blockSize)
                throw new Error("Invalid input length: must be at least 2 blocks");

            const r = wrappedKey.length / cipher.blockSize - 1;
            const n = 2 * (r + 1);
            const v = (n - 1) * 6;
            const qLen = (n - 1) * half;
            const B = wrappedKey.slice(0, half);
            const q = wrappedKey.slice(half, half + qLen);

            const block = new Uint8Array(cipher.blockSize);
            for (let i = v; i >= 1; i--) {
                block.set(q.subarray(qLen - half));
                block.set(B, half);
                block[half] ^= i & 0xff;
                block[half + 1] ^= (i >>> 8) & 0xff;
                block[half + 2] ^= (i >>> 16) & 0xff;
                block[half + 3] ^= (i >>> 24) & 0xff;
                const decrypted = cipher.decrypt(block);

                q.copyWithin(half, 0, qLen - half);
                q.set(decrypted.subarray(half));

                B.set(decrypted.subarray(0, half));
            }

            let mismatch = 0;
            for (let k = qLen - cipher.blockSize; k < qLen; k++) mismatch |= q[k];
            if (mismatch != 0)
                throw new Error("KW checksum mismatch");

            const recovered = concatBytes(B,q);
            let current_length = unpad(recovered, cipher.blockSize).length;
            if (current_length % cipher.blockSize !== 0) current_length -= half + 1;

            return recovered.slice(0, current_length);
        },
    });
};