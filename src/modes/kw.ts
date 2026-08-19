import type { TArg, TRet } from "@noble/hashes/utils.js";
import type { Kalyna } from "../kalyna/index.js";
import { pad, unpad } from "../padding.js";

export const kw = (cipher: Kalyna) => {
    const block_size_kw_byte = cipher.blockSize >> 1;

    return Object.freeze({
        wrap: (key: TArg<Uint8Array>): TRet<Uint8Array> => {
            let plain_data_size_byte = key.length;
            const cipher_data = new Uint8Array(plain_data_size_byte + (cipher.blockSize << 2));
            cipher_data.set(key);

            let i = 0;
            if (plain_data_size_byte % cipher.blockSize !== 0) {
                let bitLength = plain_data_size_byte << 3;
                while (bitLength > 0) {
                    cipher_data[plain_data_size_byte + i] = bitLength & 0xFF;
                    i++;
                    bitLength >>>= 8;
                }

                plain_data_size_byte += block_size_kw_byte;

                const paddedData = pad(cipher_data.subarray(0, plain_data_size_byte), cipher.blockSize);
                cipher_data.set(paddedData, 0);
                plain_data_size_byte = paddedData.length;
            }

            const r = Math.floor(plain_data_size_byte / cipher.blockSize),
                n = 2 * (r + 1),
                v = (n - 1) * 6;

            plain_data_size_byte += cipher.blockSize;

            const b_el_count = (n - 1) * block_size_kw_byte,
                b_last_el = (n - 2) * block_size_kw_byte;

            const b = new Uint8Array(n * block_size_kw_byte),
                shift = new Uint8Array(n * block_size_kw_byte),
                B = new Uint8Array(block_size_kw_byte),
                swap = new Uint8Array(cipher.blockSize);

            B.set(cipher_data.subarray(0, block_size_kw_byte));
            b.set(cipher_data.subarray(block_size_kw_byte, block_size_kw_byte + b_el_count));

            for (i = 1; i <= v; i++) {
                swap.set(B, 0);
                swap.set(b.subarray(0, block_size_kw_byte), block_size_kw_byte);
                swap.set(cipher.encrypt(swap));
                swap[block_size_kw_byte] ^= i;
                B.set(swap.subarray(block_size_kw_byte, cipher.blockSize));
                shift.set(b.subarray(block_size_kw_byte, b_el_count));
                b.set(shift.subarray(0, b_el_count - block_size_kw_byte), 0);
                b.set(swap.subarray(0, block_size_kw_byte), b_last_el);
            }

            cipher_data.set(B, 0);
            cipher_data.set(b.subarray(0, b_el_count), block_size_kw_byte);

            return cipher_data.subarray(0, b_el_count + block_size_kw_byte);
        },
        unwrap: (wrappedKey: TArg<Uint8Array>): TRet<Uint8Array> => {
            const cipher_data = new Uint8Array(wrappedKey);
            if (cipher_data.length < 2 * cipher.blockSize)
                throw new Error("Invalid input length: must be at least 2 blocks");

            const r = Math.floor(cipher_data.length / cipher.blockSize) - 1,
                n = 2 * (r + 1),
                v = (n - 1) * 6;
            if (r < 0 || n <= 0 || v < 0)
                throw new Error("Invalid input length for decryption");

            const B = new Uint8Array(block_size_kw_byte);
            B.set(cipher_data.subarray(0, block_size_kw_byte));

            const b_el_count = (n - 1) * block_size_kw_byte;
            const b = new Uint8Array(cipher_data.length);
            b.set(cipher_data.subarray(block_size_kw_byte, block_size_kw_byte + b_el_count));

            const b_last_el = (n - 2) * block_size_kw_byte;
            const shift = new Uint8Array(cipher_data.length),
                swap = new Uint8Array(cipher.blockSize);

            for (let i = v; i >= 1; i--) {
                swap.set(b.subarray(b_last_el, b_last_el + block_size_kw_byte), 0);
                B[0] ^= i;
                swap.set(B, block_size_kw_byte);
                swap.set(cipher.decrypt(swap));
                B.set(swap.subarray(0, block_size_kw_byte));
                shift.set(b.subarray(0, b_el_count - block_size_kw_byte));
                b.set(shift.subarray(0, b_el_count - block_size_kw_byte), block_size_kw_byte);
                b.set(swap.subarray(block_size_kw_byte, cipher.blockSize), 0);
            }

            cipher_data.set(B, 0);
            cipher_data.set(b.subarray(0, b_el_count), block_size_kw_byte);

            let current_length = unpad(cipher_data, cipher.blockSize).length;
            if (current_length % cipher.blockSize !== 0) current_length -= block_size_kw_byte + 1;

            return cipher_data.slice(0, current_length);
        }
    });
}