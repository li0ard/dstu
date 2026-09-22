import { randomBytes, type CHash, type Hash, type TArg, type TRet } from "@noble/hashes/utils.js";
import { Dstu9311, gost3431195 } from "../dstu9311/index.js";
import { Kalyna256 } from "../kalyna/index.js";
import { keyWrap } from "../keywrap.js";
import { cfb } from "../modes/cfb.js";
import { kupyna256 } from "../kupyna/index.js";
import type { ECDSA } from "../types.js";
import { iso15946_kdf } from "../iso15946.js";

/** Encrypted message */
export type EncryptedMessage = {
    /** User keying material (UKM) for KDF */
    ukm?: TArg<Uint8Array>;
    /** Encryption IV */
    iv: TArg<Uint8Array>;
    /** Wrapped encryption key */
    wcek: TArg<Uint8Array>;
    /** Encrypted message */
    data: TArg<Uint8Array>;
}

/**
 * ECIES schema over DSTU 4145-2002.
 * @param curve - Curve to use.
 * @param hash - Hash function to use. (Output length must be 32 bytes)
 * @param withCofactor - Whether to multiply shared key by curve cofactor (See {@link types!ECDSA.getSharedSecret ECDSA.getSharedSecret})
 * @param useDstu9311 - Whether to use DSTU 9311:2024 instead of Kalyna-256?
 */
export const dstu4145Encrypter = (
    curve: ECDSA,
    hash: CHash<Hash<any>>,
    withCofactor = true,
    useDstu9311 = false
) => {
    const oid = useDstu9311 ? "1.2.804.2.1.1.1.1.1.1.5" : "1.2.804.2.1.1.1.1.1.3.11";
    const Cipher = useDstu9311 ? Dstu9311 : Kalyna256;
    const macLength = useDstu9311 ? 8 : 32;

    const getSharedSecret = (
        sharedKey: TArg<Uint8Array>,
        ukm?: TArg<Uint8Array>
    ): TRet<Uint8Array> => iso15946_kdf(hash, oid, sharedKey, ukm);

    return Object.freeze({
        /**
         * Encrypt message
         * @param secretKeyA - Sender secret key.
         * @param publicKeyB - Recipient public key.
         * @param plaintext - Message to encrypt.
         */
        encrypt: (
            secretKeyA: TArg<Uint8Array>,
            publicKeyB: TArg<Uint8Array>,
            plaintext: TArg<Uint8Array>
        ): EncryptedMessage => {
            const cek = randomBytes(32),
                ukm = randomBytes(64),
                iv = randomBytes(macLength);

            const sharedKey = getSharedSecret(
                curve.getSharedSecret(secretKeyA, publicKeyB, withCofactor),
                ukm
            );
            const wcek = keyWrap(sharedKey, useDstu9311).wrap(cek, iv);
            const data = cfb(new Cipher(cek), iv).encrypt(plaintext);

            return { ukm, iv, wcek, data }
        },
        /**
         * Decrypt message
         * @param secretKeyB - Recipient secret key.
         * @param publicKeyA - Sender public key.
         * @param encryptedMessage - Encrypted message object.
         */
        decrypt: (
            secretKeyB: TArg<Uint8Array>,
            publicKeyA: TArg<Uint8Array>,
            encryptedMessage: EncryptedMessage
        ): TRet<Uint8Array> => {
            const sharedKey = getSharedSecret(
                curve.getSharedSecret(secretKeyB, publicKeyA, withCofactor),
                encryptedMessage.ukm
            );
            const cek = keyWrap(sharedKey, useDstu9311).unwrap(encryptedMessage.wcek);

            return cfb(new Cipher(cek), encryptedMessage.iv).decrypt(encryptedMessage.data);
        }
    });
}

/** 
 * ECIES schema over DSTU 4145-2002.
 * 
 * Uses GOST 34.311-95 as hash function.
 * @param curve - Curve to use.
 * @param withCofactor - Whether to multiply shared key by curve cofactor (See {@link types!ECDSA.getSharedSecret ECDSA.getSharedSecret})
 */
export const dstu4145EncrypterWithGost = (curve: ECDSA, withCofactor?: boolean) =>
    dstu4145Encrypter(curve, gost3431195, withCofactor, true);

/** 
 * ECIES schema over DSTU 4145-2002.
 * 
 * Uses Kupyna-256 as hash function.
 * @param curve - Curve to use.
 * @param withCofactor - Whether to multiply shared key by curve cofactor (See {@link types!ECDSA.getSharedSecret ECDSA.getSharedSecret})
 */
export const dstu4145EncrypterWithKupyna = (curve: ECDSA, withCofactor?: boolean) =>
    dstu4145Encrypter(curve, kupyna256, withCofactor);