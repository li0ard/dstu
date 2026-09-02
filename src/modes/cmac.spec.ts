import { describe, test, expect } from "bun:test";
import type { Kalyna } from "../kalyna";
import { cmac } from "./cmac";
import { hexToBytes, type TRet } from "@noble/hashes/utils.js";
import { kalyna128, kalyna128_256, kalyna512 } from "./_test_utils.test";

const performTest = (
    cipher: Kalyna,
    msg: Uint8Array,
    mac: Uint8Array,
) => {
    const mode = cmac(cipher);
    expect(mode.compute(msg)).toStrictEqual(mac as TRet<Uint8Array>);
}

describe("[MODE] CMAC", () => {
    test("#1", () => performTest(
        kalyna128,
        hexToBytes("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F"),
        hexToBytes("123B4EAB8E63ECF3E645A99C1115E241")
    ));

    test("#2", () => performTest(
        kalyna128_256,
        hexToBytes("303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D"),
        hexToBytes("4CF52D7D5B0C47F05F6F5F5E73C3B508")
    ));

    test("#3", () => performTest(
        kalyna512,
        hexToBytes(
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F" +
            "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
        ),
        hexToBytes("7279FA6BC8EF7525B2B35260D00A1743")
    ));
});