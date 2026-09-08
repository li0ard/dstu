import { describe, test, expect } from "bun:test";
import { gmac } from "./gmac";
import { hexToBytes, type TRet } from "@noble/hashes/utils.js";
import { alphabet, kalyna128_256, kalyna256, kalyna256_512, kalyna512 } from "./_test_utils.test";
import type { Cipher } from "../types";

const performTest = (
    cipher: Cipher,
    msg: Uint8Array,
    aad: Uint8Array,
    mac: Uint8Array,
    q = 16
) => {
    const mode = gmac(cipher, q);
    expect(mode.compute(aad, msg)).toStrictEqual(mac as TRet<Uint8Array>);
}

describe("[MODE] GMAC", () => {
    test("#1", () => performTest(
        kalyna128_256,
        new Uint8Array(),
        alphabet.subarray(48,64),
        hexToBytes("5AE309EE80B583C6523397ADCB5704C4")
    ));

    test("#2", () => performTest(
        kalyna256,
        new Uint8Array(),
        alphabet.subarray(64,96),
        hexToBytes("FF48B56F2C26CC484B8F5952D7B3E1FE69577701C50BE96517B33921E44634CD"),
        32
    ));

    test("#3", () => performTest(
        kalyna256_512,
        new Uint8Array(),
        alphabet.subarray(96,128),
        hexToBytes("96F61FA0FDE92883C5041D748F9AE91F3A0A50415BFA1466855340A5714DC01F"),
        32
    ));

    test("#4", () => performTest(
        kalyna512,
        new Uint8Array(),
        alphabet.subarray(128,192),
        hexToBytes("897C32E05E776FD988C5171FE70BB72949172E514E3308A871BA5BD898FB6EBD6E3897D2D55697D90D6428216C08052E3A5E7D4626F4DBBF1546CE21637357A3"),
        64
    ));
});