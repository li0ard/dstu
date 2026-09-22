import type { TArg, TRet } from "@noble/hashes/utils.js";

/** Cipher or hash function wrapper */
export type CipherOrHashFunctionWrapper = (msg: TArg<Uint8Array>) => TRet<Uint8Array>;

/** Cipher core */
export type Cipher = {
    /** Block size */
    readonly blockSize: number;
    /** Key size */
    readonly keySize: number;
    /** Encrypt block */
    encrypt(plaintext: TArg<Uint8Array>): TRet<Uint8Array>;
    /** Decrypt block */
    decrypt(ciphertext: TArg<Uint8Array>): TRet<Uint8Array>;
}

export type StreamCipher = {
    /** Block size */
    readonly blockSize: number;
    /** Key size */
    readonly keySize: number;
    /** Generate keystream word */
    next_stream(): TRet<Uint8Array>;
    /** Perform encryption/decryption */
    crypt(msg: TArg<Uint8Array>): TRet<Uint8Array>;
}

/** Block mode for {@link Cipher} */
export type BlockMode = {
    /** Encrypt plaintext */
    encrypt: (plaintext: TArg<Uint8Array>) => TRet<Uint8Array>;
    /** Decrypt ciphertext */
    decrypt: (ciphertext: TArg<Uint8Array>) => TRet<Uint8Array>;
}

/** Stream-like mode for {@link Cipher} */
export type StreamMode = {
    /** Proceed message */
    crypt: CipherOrHashFunctionWrapper;
}

/** MAC mode for {@link Cipher} */
export type MACMode = {
    /** Compute MAC */
    compute: CipherOrHashFunctionWrapper;
}

/** GMAC mode for {@link Cipher} */
export type GMACMode = {
    /** Compute MAC */
    compute: (msg: TArg<Uint8Array>, aad?: TArg<Uint8Array>) => TRet<Uint8Array>;
}

/** AEAD mode for {@link Cipher} */
export type AEADMode = {
    /** Seal plaintext and AAD */
    seal: (plaintext: TArg<Uint8Array>, aad?: TArg<Uint8Array>) => TRet<Uint8Array>;
    /** Open ciphertext and AAD */
    open: (ciphertext: TArg<Uint8Array>, aad?: TArg<Uint8Array>) => TRet<Uint8Array>;
}

/** Key wrap mode for {@link Cipher} */
export type WrapMode = {
    /** Wrap encryption key */
    wrap: (key: TArg<Uint8Array>) => TRet<Uint8Array>;
    /** Unwrap encryption key */
    unwrap: (wrappedKey: TArg<Uint8Array>) => TRet<Uint8Array>;
}

/** Disk encryption mode for {@link Cipher} */
export type DiskMode = {
    /** Encrypt disk sector */
    encrypt: (plaintext: TArg<Uint8Array>, tweak: TArg<Uint8Array>) => TRet<Uint8Array>;
    /** Decrypt disk sector */
    decrypt: (ciphertext: TArg<Uint8Array>, tweak: TArg<Uint8Array>) => TRet<Uint8Array>;
}

/** ECDSA signer */
export type ECDSA = {
    /**
     * Computes public key for a secret key
     * @param isCompressed - Whether to return compact (default), or full key
     * @returns Public key, full when `isCompressed=false`; short when `isCompressed=true`
     */
    getPublicKey: (secretKey: TArg<Uint8Array>, isCompressed?: boolean) =>TRet<Uint8Array>;
    /** 
     * Signs a message hash with a secret key.
     * @param secretKey - Secret key bytes.
     * @param digest - Digest bytes.
     * @param rand - Optional parameter for ephemeral key
     * @returns Encoded signature bytes.
     */
    sign:(secretKey: TArg<Uint8Array>, digest: TArg<Uint8Array>, rand?: TArg<Uint8Array>) => TRet<Uint8Array>;
    /**
     * Verifies a signature against message hash and public key.
     * @param publicKey - Public key
     * @param digest - Digest bytes
     * @param signature - Encoded signature bytes.
     * @returns Whether the signature is valid.
     */
    verify: (publicKey: TArg<Uint8Array>, digest: TArg<Uint8Array>, signature: TArg<Uint8Array>) => boolean;
    /**
     * Compute the shared secret point from a secret key and peer public key.
     * @param secretKeyA - Local secret key bytes.
     * @param publicKeyB - Peer public key bytes.
     * @param withCofactor - Whether to multiply result by curve cofactor? (default - `true`).
     * @returns Encoded shared point.
     */
    getSharedSecret: (secretKeyA: TArg<Uint8Array>, publicKeyB: TArg<Uint8Array>, withCofactor?: boolean) => TRet<Uint8Array>;

    /**
     * Generate a secret/public key pair.
     * @param isCompressed - Whether to return compact (default), or full key
     * @returns Secret/public key pair.
     */
    keygen: (isCompressed?: boolean) => KeyPair

    /** Byte lengths for keys and signatures exposed by this curve. */
    lengths: Readonly<{
        fieldByteLength: number;
        pointByteLength: number;
        scalarByteLength: number;
        signatureByteLength: number;
    }>
}

/** Keypair */
export type KeyPair = {
    /** Secret key */
    secretKey: TArg<Uint8Array>;
    /** Public key */
    publicKey: TArg<Uint8Array>;
}