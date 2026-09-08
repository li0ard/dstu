import { describe, test, expect } from "bun:test";
import { ecb } from "./ecb";
import { hexToBytes, type TRet } from "@noble/hashes/utils.js";
import { IV128, IV128_256, IV256, IV256_512, IV512, kalyna128, kalyna128_256, kalyna256, kalyna256_512, kalyna512 } from "./_test_utils.test";
import type { Cipher } from "../types";

const performTest = (
    cipher: Cipher,
    pt: Uint8Array,
    ct: Uint8Array
) => {
    const mode = ecb(cipher);
    expect(mode.encrypt(pt)).toStrictEqual(ct as TRet<Uint8Array>);
    expect(mode.decrypt(ct)).toStrictEqual(pt as TRet<Uint8Array>);
}

describe("[MODE] ECB", () => {
    test("#1", () => performTest(
        kalyna128,
        IV128,
        hexToBytes("81BF1C7D779BAC20E1C9EA39B4D2AD06")
    ));

    test("#2", () => performTest(
        kalyna128_256,
        IV128_256,
        hexToBytes("58EC3E091000158A1148F7166F334F14")
    ));

    test("#3", () => performTest(
        kalyna256,
        IV256,
        hexToBytes("F66E3D570EC92135AEDAE323DCBD2A8CA03963EC206A0D5A88385C24617FD92C")
    ));

    test("#4", () => performTest(
        kalyna256_512,
        IV256_512,
        hexToBytes("606990E9E6B7B67A4BD6D893D72268B78E02C83C3CD7E102FD2E74A8FDFE5DD9")
    ));

    test("#5", () => performTest(
        kalyna512,
        IV512,
        hexToBytes("4A26E31B811C356AA61DD6CA0596231A67BA8354AA47F3A13E1DEEC320EB56B895D0F417175BAB662FD6F134BB15C86CCB906A26856EFEB7C5BC6472940DD9D9")
    ));
});