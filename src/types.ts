import type { TArg, TRet } from "@noble/hashes/utils.js";

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
    crypt: (msg: TArg<Uint8Array>) => TRet<Uint8Array>;
}

/** MAC mode for {@link Cipher} */
export type MACMode = {
    /** Compute MAC */
    compute: (msg: TArg<Uint8Array>) => TRet<Uint8Array>;
}

/** GMAC mode for {@link Cipher} */
export type GMACMode = {
    /** Compute MAC */
    compute: (aad: TArg<Uint8Array>, msg: TArg<Uint8Array>) => TRet<Uint8Array>;
}

/** AEAD mode for {@link Cipher} */
export type AEADMode = {
    /** Seal plaintext and AAD */
    seal: (plaintext: TArg<Uint8Array>, aad?: TArg<Uint8Array>) => TRet<Uint8Array>;
    /** Open ciphertext and AAD */
    open: (ciphertext: TArg<Uint8Array>, aad?: TArg<Uint8Array>) => TRet<Uint8Array>;
}
