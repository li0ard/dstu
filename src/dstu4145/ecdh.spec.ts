import { describe, test, expect } from "bun:test";
import { dstu257, dstu4145, dstu431, DSTU_233_ONB } from ".";

const performTest = (signer: ReturnType<typeof dstu4145>) => {
    const a = signer.keygen();
    const b = signer.keygen();

    const sharedA = signer.getSharedKey(a.secretKey, b.publicKey);
    const sharedB = signer.getSharedKey(b.secretKey, a.publicKey);
    expect(sharedA).toStrictEqual(sharedB);
}

const dstu233_onb = dstu4145(DSTU_233_ONB);
describe("[ECDH] DSTU 4145-2002 (PB)", () => {
    test("#1 (m=257)", () => performTest(dstu257));
    test("#2 (m=431)", () => performTest(dstu431));
});

describe("[ECDH] DSTU 4145-2002 (ONB)", () => {
    test("#1 (m=233)", () => performTest(dstu233_onb));
});