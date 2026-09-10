import { describe, test, expect } from "bun:test";
import { cfb } from "./cfb";
import { hexToBytes, type TRet } from "@noble/hashes/utils.js";
import { alphabet, getTestDstu9311, IV128, IV128_256_rev, IV256, IV256_512, IV512, kalyna128, kalyna128_256_rev, kalyna256, kalyna256_512, kalyna512 } from "./_test_utils.test";
import type { Cipher } from "../types";

const performTest = (
    cipher: Cipher,
    iv: Uint8Array,
    pt: Uint8Array,
    ct: Uint8Array,
    q = cipher.blockSize
) => {
    const mode = cfb(cipher, iv, q);
    expect(mode.encrypt(pt)).toStrictEqual(ct as TRet<Uint8Array>);
    expect(mode.decrypt(ct)).toStrictEqual(pt as TRet<Uint8Array>);
}

describe("[MODE] CFB", () => {
    test("#1", () => performTest(
        kalyna128,
        IV128,
        alphabet.subarray(32, 80),
        hexToBytes("A19E3E5E53BE8A07C9E0C01298FF83291F8EE6212110BE3FA5C72C88A082520B265570FE28680719D9B4465E169BC37A")
    ));

    test("#2", () => performTest(
        kalyna128_256_rev,
        IV128_256_rev,
        hexToBytes("26319A368D85DE43DD5FDB928D91A441493D8CE07B64797C8F9676C5921CD1EA743F5E2777C327AC58"),
        alphabet.slice(55, 96).reverse(),
        8
    ));

    test("#3", () => performTest(
        kalyna256,
        IV256,
        alphabet.subarray(64, 145),
        hexToBytes("E07821AF642F4B1DC071166F2D329763C2CF3B9E39CD0B52BDD33A0DC7B6B6BB201C4A1CD0F5DCB693ABEEA120DACA3A29C73D1D6E87FD75B7DE9E3BE4D256791C2E44583DE8E061E45834A24262BDEBBE"),
        16
    ));

    test("#4", () => performTest(
        kalyna256_512,
        IV256_512,
        alphabet.subarray(96, 177),
        hexToBytes("0008F28A82D2D01D23BFB2F8BB4F06D8FE73BA4F48A2977585570ED3818323A6DBAD3D9DD580D9D8F787CE55FAB90735F6B2D6152D56C0C787E6F4B6A2F557DF707A671D06AED196DD7D7E2320D8E45C4C")
    ));

    test("#5", () => performTest(
        kalyna512,
        IV512,
        alphabet.subarray(128, 225),
        hexToBytes(
            "CAA761980599B3ED2E945C41891BAD95F72B11C73ED26536A6847458BC76C827357156B4B3FE0DC1877F5B9F17B866C3" +
            "7B21D89531DB48007D05DEC928B06766C67D6F3F4C2B82D7A836FAD160905C1C7576243877DC3ADE4AA057966E0023F0" +
            "69"
        )
    ));
});

describe("[MODE] CFB (DSTU 9311:2024)", () => {
    test("#1", () => performTest(
        getTestDstu9311(hexToBytes("0100000002000000030000000400000005000000060000000700000008000000")),
        hexToBytes("0300000003000000"),
        alphabet.subarray(1, 25),
        hexToBytes("d1ce841aa50de523b0ab76646f0d1ee8ae02aa0c4e8eafb3")
    ));
});