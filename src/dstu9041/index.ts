import { bytesToNumberBE, concatBytes, equalBytes, numberToBytesBE, type TArg, type TRet } from "@noble/curves/utils.js";
import { kupyna256 } from "../kupyna/index.js";
import { curve256, curve512, dstu9041Curve } from "./curve.js";
import { kw } from "../modes/index.js";
import { Kalyna256, Kalyna512 } from "../kalyna/index.js";
import { randomBytes } from "@noble/hashes/utils.js";

const ID_KUPYNA256 = 1;

const dstu9041 = (length: 256 | 512) => {
    let MAX_LENGTH: number,
        HASH_LENGTH_BYTES: number, 
        curve: ReturnType<typeof dstu9041Curve>,
        Сipher: typeof Kalyna256 | typeof Kalyna512;
    switch(length) {
        case 256:
            MAX_LENGTH = 200;
            HASH_LENGTH_BYTES = 4;
            curve = curve256;
            Сipher = Kalyna256;
        break;
        case 512:
            MAX_LENGTH = 424;
            HASH_LENGTH_BYTES = 8;
            curve = curve512;
            Сipher = Kalyna512;
        break;
        default:
            throw new Error("Invalid length, supported only 256 and 512 bits");
    }
    const PADDED_MESSAGE_BYTES = MAX_LENGTH / 8, 
        STRUCT_BYTES = 1 + HASH_LENGTH_BYTES + 2 + PADDED_MESSAGE_BYTES,
        { Point } = curve, { Fp, Fn } = Point;

    const padMessage = (message: TArg<Uint8Array>): TRet<Uint8Array> => {
        if(message.length == 0) throw new Error("Invalid message length");
        if(message.length > PADDED_MESSAGE_BYTES) throw new Error("Message too long");

        const paddedMessage = new Uint8Array(PADDED_MESSAGE_BYTES);
        paddedMessage.set(message, PADDED_MESSAGE_BYTES - message.length);

        return paddedMessage;
    }

    const buildStruct = (message: TArg<Uint8Array>): TRet<Uint8Array> => {
        const paddedMessage = padMessage(message);
        const messageLength = numberToBytesBE(message.length * 8, 2);
        const digest = kupyna256(concatBytes(messageLength, paddedMessage)).subarray(-HASH_LENGTH_BYTES);

        const struct = new Uint8Array(STRUCT_BYTES);
        struct[0] = ID_KUPYNA256;
        struct.set(digest, 1);
        struct.set(messageLength, 1 + HASH_LENGTH_BYTES);
        struct.set(paddedMessage, 3 + HASH_LENGTH_BYTES);

        return struct;
    }

    const parseStruct = (struct: TArg<Uint8Array>): TRet<Uint8Array> => {
        if(struct.length != STRUCT_BYTES) throw new Error("Invalid ciphertext");
        if(struct[0] != ID_KUPYNA256) throw new Error("Invalid hash ID");

        const embeddedHash = struct.subarray(1, HASH_LENGTH_BYTES + 1);
        const messageLength = struct.subarray(1 + HASH_LENGTH_BYTES, 3 + HASH_LENGTH_BYTES);
        const paddedMessage = struct.subarray(3 + HASH_LENGTH_BYTES);

        const messageBits = Number(bytesToNumberBE(messageLength));
        if(messageBits == 0) throw new Error("Invalid message length");
        if(messageBits > MAX_LENGTH) throw new Error("Message too long");

        // message len + padded message
        const digest = kupyna256(struct.subarray(1 + HASH_LENGTH_BYTES)).subarray(-HASH_LENGTH_BYTES);
        if(!equalBytes(embeddedHash, digest))
            throw new Error("Integrity check failed, hash mismatch");

        const messageBytes = Math.ceil(messageBits / 8);
        const paddingLen = PADDED_MESSAGE_BYTES - messageBytes;
        let invalidPadding = 0;
        for(let i = 0; i < paddedMessage.length; i++)
            invalidPadding |= (i < paddingLen ? 1 : 0) & (paddedMessage[i] != 0 ? 1 : 0);
        if(invalidPadding != 0) throw new Error("Invalid padding");

        return paddedMessage.slice(paddingLen);
    }

    return Object.freeze({
        getPublicKey: curve.getPublicKey,
        keygen: curve.keygen,
        encrypt: (plaintext: TArg<Uint8Array>, publicKey: TArg<Uint8Array>, rand?: TArg<Uint8Array>): TRet<Uint8Array> => {
            const struct = buildStruct(plaintext);

            const e = Fn.create(bytesToNumberBE(rand ?? randomBytes(STRUCT_BYTES)));
            const r = Fp.toBytes(Point.BASE.multiply(e).x);
            const key = Fp.toBytes(Point.fromBytes(publicKey).multiply(e).x);

            const plaintext_kw = new Uint8Array(2 * STRUCT_BYTES);
            plaintext_kw.set(struct);
            const ciphertext = kw(new Сipher(key)).wrap(plaintext_kw);

            return concatBytes(r, ciphertext);
        },
        decrypt: (ciphertext: TArg<Uint8Array>, privateKey: TArg<Uint8Array>): TRet<Uint8Array> => {
            if(ciphertext.length != length / 2) throw new Error("Invalid ciphertext length");

            const r = bytesToNumberBE(ciphertext.subarray(0, STRUCT_BYTES));
            if(!Fp.isValidNot0(r)) throw new Error("Invalid ciphertext");

            const T = Point.fromX(r).multiply(bytesToNumberBE(privateKey));
            const key = Fp.toBytes(T.x);
            const plaintext = kw(new Сipher(key)).unwrap(ciphertext.subarray(STRUCT_BYTES));

            return parseStruct(plaintext.subarray(0, STRUCT_BYTES));
        }
    });
}

/** DSTU 9041:2020 (256 bit) */
export const dstu9041_256 = dstu9041(256);
/** DSTU 9041:2020 (512 bit) */
export const dstu9041_512 = dstu9041(512);