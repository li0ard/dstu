import { randomBytes, type CHash, type Hash, type TArg, type TRet } from "@noble/hashes/utils.js";
import { AsnConvert, AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";
import { AlgorithmIdentifier } from "@peculiar/asn1-x509";
import { Dstu9311, gost3431195, Gost3431195 } from "../dstu9311/index.js";
import { Kalyna256 } from "../kalyna/index.js";
import { keyWrap } from "../keywrap.js";
import { cfb } from "../modes/cfb.js";
import { kupyna256 } from "../kupyna/index.js";
import type { ECDSA } from "../types.js";

/**
 * ```asn1
 * SharedInfo ::= SEQUENCE {
 *   keyInfo AlgorithmIdentifier,
 *   entityInfo [0] EXPLICIT OCTET STRING OPTIONAL,
 *   suppPubInfo  [2] EXPLICIT OCTET STRING }
 * ```
 */
class SharedInfo {
    @AsnProp({ type: AlgorithmIdentifier })
    keyInfo = new AlgorithmIdentifier();

    @AsnProp({ type: AsnPropTypes.OctetString, context: 0, optional: true })
    entityInfo?: ArrayBuffer;

    @AsnProp({ type: AsnPropTypes.OctetString, context: 2 })
    suppPubInfo = new ArrayBuffer(0);

    constructor(params: Partial<SharedInfo> = {}) {
        Object.assign(this, params);
    }
}

const removeLeadZeros = (bytes: TArg<Uint8Array>): TRet<Uint8Array> => {
    const idx = bytes.findIndex(i => i !== 0);
    return idx === -1 ? new Uint8Array() : bytes.slice(idx);
}

const KEY_LENGTH = new Uint8Array([0,0,1,0]);
const COUNTER = new Uint8Array([0,0,0,1]);

const encodeSharedInfo = (oid: string, ukm?: TArg<Uint8Array>) => new Uint8Array(AsnConvert.serialize(
    new SharedInfo({
        keyInfo: new AlgorithmIdentifier({
            algorithm: oid,
            parameters: null
        }),
        entityInfo: ukm as ArrayBuffer | undefined,
        suppPubInfo: KEY_LENGTH.buffer
    })
));

/** Encrypted message */
export type EncryptedMessage = {
    /** User keying material (UKM) for KDF */
    ukm: TArg<Uint8Array>;
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
    if(hash.outputLen != 32)
        throw new Error("Invalid hash function. Output length must be 32 bytes");

    const oid = useDstu9311 ? "1.2.804.2.1.1.1.1.1.1.5" : "1.2.804.2.1.1.1.1.1.3.11";
    const Cipher = useDstu9311 ? Dstu9311 : Kalyna256;
    const macLength = useDstu9311 ? 8 : 32;

    const getSharedSecret = (
        sharedKey: TArg<Uint8Array>,
        ukm?: TArg<Uint8Array>
    ): TRet<Uint8Array> => {
        const hasher = hash.create();
        if(hasher instanceof Gost3431195) hasher.update(removeLeadZeros(sharedKey));
        else hasher.update(sharedKey);

        return hasher.update(COUNTER).update(encodeSharedInfo(oid, ukm)).digest();
    }

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