import { describe, test, expect } from "bun:test";
import { cmac } from "./cmac";
import { hexToBytes, type TRet } from "@noble/hashes/utils.js";
import { alphabet, kalyna128, kalyna128_256, kalyna512 } from "./_test_utils.test";
import type { Cipher } from "../types";

const performTest = (
    cipher: Cipher,
    msg: Uint8Array,
    mac: Uint8Array,
) => {
    const mode = cmac(cipher);
    expect(mode.compute(msg)).toStrictEqual(mac as TRet<Uint8Array>);
}

describe("[MODE] CMAC", () => {
    test("#1", () => performTest(
        kalyna128,
        alphabet.subarray(32, 80),
        hexToBytes("123B4EAB8E63ECF3E645A99C1115E241")
    ));

    test("#2", () => performTest(
        kalyna128_256,
        alphabet.subarray(48, 142),
        hexToBytes("4CF52D7D5B0C47F05F6F5F5E73C3B508")
    ));

    test("#3", () => performTest(
        kalyna512,
        alphabet.subarray(64, 192),
        hexToBytes("7279FA6BC8EF7525B2B35260D00A1743")
    ));
});