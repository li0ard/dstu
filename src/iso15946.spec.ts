// Test vectors from "Наказ № 112 від 14.05.2010 Про затвердження Технічних специфікацій форматів криптографічних повідомлень. Захищені дані"
import { describe, test, expect } from "bun:test";
import { hexToBytes, type TRet } from "@noble/hashes/utils.js";
import type { CHash } from "@noble/curves/utils.js";
import { gost3431195 } from "./dstu9311";
import { iso15946_kdf } from "./iso15946";

const performTest = (
    hash: CHash,
    oid: string,
    inputData: Uint8Array,
    expected: Uint8Array,
    ukm?: Uint8Array
) => expect(iso15946_kdf(hash, oid, inputData, ukm)).toStrictEqual(expected as TRet<Uint8Array>);

const ukm = hexToBytes("0123456789abcdeffedcba98765432010123456789abcdeffedcba98765432010123456789abcdeffedcba98765432010123456789abcdeffedcba9876543201");

describe("[KDF] ISO 15946", () => {
    test("#1", () => performTest(
        gost3431195,
        "1.2.804.2.1.1.1.1.1.1.3",
        hexToBytes("0534190674D93B3D2327D6B065207F9DE7806365CC"),
        hexToBytes("6BCC82B8F7A8BC9FC8B9BD4CDE18FCFE99711755D9AC05422C3332F3E96D49B8"),
    ));

    test("#2", () => performTest(
        gost3431195,
        "1.2.804.2.1.1.1.1.1.1.3",
        hexToBytes("03AC78ADA30FC2CBC8F84E64F4090F816AF6B6B068F0"),
        hexToBytes("4D0AEE861B17C25EAD82AA16544495BC79DEC98C3D7B85BF3C3BDD2FDCC9B9ED"),
        ukm
    ));

    test("#3", () => performTest(
        gost3431195,
        "1.2.804.2.1.1.1.1.1.1.2",
        hexToBytes("07F84ADBA62457C5DA5D959447C4F6C1864C9B288E"),
        hexToBytes("9F619411BB8D53C69CA7C003691070EF31C7B72B6368311033ABEFB8A0C12C9D"),
        ukm
    ));
});