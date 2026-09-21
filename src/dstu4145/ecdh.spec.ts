// Test vectors from "Наказ № 112 від 14.05.2010 Про затвердження Технічних специфікацій форматів криптографічних повідомлень. Захищені дані"
import { describe, test, expect } from "bun:test";
import { dstu163, dstu4145, dstu431, DSTU_173_ONB } from ".";
import { hexToBytes, type TRet } from "@noble/hashes/utils.js";
import type { ECDSA } from "../types";

const performTest = (
    signer: ECDSA,
    aSk: Uint8Array,
    bSk: Uint8Array,
    expectedShared: Uint8Array
) => {
    const aPk = signer.getPublicKey(aSk);
    const bPk = signer.getPublicKey(bSk);

    const sharedA = signer.getSharedSecret(aSk, bPk);
    const sharedB = signer.getSharedSecret(bSk, aPk);

    expect(sharedA).toStrictEqual(sharedB);
    expect(sharedA).toStrictEqual(expectedShared as TRet<Uint8Array>);
    expect(sharedB).toStrictEqual(expectedShared as TRet<Uint8Array>);
}

describe("[ECDH] DSTU 4145-2002 (PB)", () => {
    test("#1 (m=163)", () => performTest(
        dstu163,
        hexToBytes("0304991F9AC1A8094F6FBFA009250D4A8099320D55"),
        hexToBytes("01FC8617116074A8FF81B42F85CA2516CF11CE2E13"),
        hexToBytes("07F84ADBA62457C5DA5D959447C4F6C1864C9B288E")
    ));

    test("#2 (m=431)", () => performTest(
        dstu431,
        hexToBytes("4B3A1707F870D0C1D4CE438E88AA2B361506916286F36FF35F9CBE9C0FBDBE1F776BB5C25878BAE1C54958D1B039B12FF547E00863"),
        hexToBytes("06FE211C555CB9D3A27B7EC2E2FFBB4CB167EE86BB7F111E7BCD8F6564E8835B09E047B9286FBA7F83507879BFEE4C33ECBA41C5DAB5"),
        hexToBytes("4BCA28D648A50DEEF85F8A34735BAE5C1AFEA72D3515E16639E5F166DD0A47EDE333EA5AB3415DBC4FDBB7B68BE249FF3C5B75F82B55")
    ));
});

describe("[ECDH] DSTU 4145-2002 (ONB)", () => {
    const aSk = hexToBytes("02A21BB46932465443580E4586770E2E244A04221A57");
    test("#1 (m=173)", () => performTest(
        dstu4145(DSTU_173_ONB),
        aSk, aSk,
        hexToBytes("03AC78ADA30FC2CBC8F84E64F4090F816AF6B6B068F0")
    ));
});