// Unfortunately, there's no test vectors for this ECIES schema (same for ECDH)
// Schema implementation based on https://github.com/dstucrypt/jkurwa/blob/master/lib/models/Priv.js
import { describe, test, expect } from "bun:test";
import { dstu257, dstu4145, dstu4145EncrypterWithKupyna, dstu431, DSTU_233_ONB } from ".";
import type { ECDSA } from "../types";

const message = new TextEncoder().encode("{'msg': 'hello', 'code': 1}");

const performTest = (signer: ECDSA) => {
    const a = signer.keygen();
    const b = signer.keygen();

    const encrypter = dstu4145EncrypterWithKupyna(signer);
    const encrypted = encrypter.encrypt(
        a.secretKey, b.publicKey,
        message
    );

    expect(encrypter.decrypt(
        b.secretKey, a.publicKey,
        encrypted
    )).toStrictEqual(message);
}

describe("[ECIES] DSTU 4145-2002 (PB)", () => {
    test("#1 (m=257)", () => performTest(dstu257));
    test("#2 (m=431)", () => performTest(dstu431));
});

describe("[ECIES] DSTU 4145-2002 (ONB)", () => {
    test("#1 (m=233)", () => performTest(dstu4145(DSTU_233_ONB)));
});