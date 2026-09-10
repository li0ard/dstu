import { describe, test, expect } from "bun:test";

import { hexToBytes, type TRet } from "@noble/hashes/utils.js";
import { Dstu9311, GOSTR_3411_94_TEST_PARAM_SET } from ".";
import type { Cipher } from "../types";

const performTest = (cipher: Cipher, pt: Uint8Array, ct: Uint8Array) => {
    expect(cipher.encrypt(pt)).toStrictEqual(ct as TRet<Uint8Array>);
    expect(cipher.decrypt(ct)).toStrictEqual(pt as TRet<Uint8Array>);
}

describe("[CORE] DSTU 9311:2024", () => {
    test("#1", () => performTest(
        new Dstu9311(hexToBytes("348724a4c1a67667153dde5933884250e3248c657d413b8c1c9ca09a56d968cf"), GOSTR_3411_94_TEST_PARAM_SET),
        hexToBytes("34c01533e37d1c56"),
        hexToBytes("863e78dd2d60d13c"),
    ));

    test("#2", () => performTest(
        new Dstu9311(hexToBytes("0100000002000000030000000400000005000000060000000700000008000000")),
        hexToBytes("0300000003000000"),
        hexToBytes("17f7f13e7f8ad4e1"),
    ));
});