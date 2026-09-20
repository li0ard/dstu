// Unfortunately, there's no test vectors for ECDH (same for ECIES schema)
// ECDH implementation based on https://github.com/specinfo-ua/UAPKI/blob/main/library/uapkic/src/ec.c#L1160
import { describe, test, expect } from "bun:test";
import { dstu257, dstu257_le, dstu4145, dstu4145_le, dstu431, dstu431_le, DSTU_233_ONB } from ".";
import type { ECDSA } from "../types";

const performTest = (signer: ECDSA) => {
    const a = signer.keygen();
    const b = signer.keygen();

    const sharedA = signer.getSharedSecret(a.secretKey, b.publicKey);
    const sharedB = signer.getSharedSecret(b.secretKey, a.publicKey);
    expect(sharedA).toStrictEqual(sharedB);
}

describe("[ECDH] DSTU 4145-2002 (PB)", () => {
    test("#1 (m=257)", () => performTest(dstu257));
    test("#2 (m=431)", () => performTest(dstu431));
    test("#3 (m=257, le)", () => performTest(dstu257_le));
    test("#4 (m=431, le)", () => performTest(dstu431_le));
});

describe("[ECDH] DSTU 4145-2002 (ONB)", () => {
    test("#1 (m=233)", () => performTest(dstu4145(DSTU_233_ONB)));
    test("#2 (m=233, le)", () => performTest(dstu4145_le(DSTU_233_ONB)));
});