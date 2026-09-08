import { describe, test, expect } from "bun:test";
import { ofb } from "./ofb";
import { hexToBytes, type TRet } from "@noble/hashes/utils.js";
import { alphabet, IV128, IV128_256, IV256, IV256_512, IV512, kalyna128, kalyna128_256, kalyna256, kalyna256_512, kalyna512 } from "./_test_utils.test";
import type { Cipher } from "../types";

const performTest = (
    cipher: Cipher,
    iv: Uint8Array,
    pt: Uint8Array,
    ct: Uint8Array,
) => {
    const mode = ofb(cipher, iv);
    expect(mode.crypt(pt)).toStrictEqual(ct as TRet<Uint8Array>);
    expect(mode.crypt(ct)).toStrictEqual(pt as TRet<Uint8Array>);
}

describe("[MODE] OFB", () => {
    test("#1", () => performTest(
        kalyna128,
        IV128,
        alphabet.subarray(32, 80),
        hexToBytes("A19E3E5E53BE8A07C9E0C01298FF832953205C661BD85A51F3A94113BC785CAB634B36E89A8FDD16A12E4467F5CC5A26")
    ));

    test("#2", () => performTest(
        kalyna128_256,
        IV128_256,
        alphabet.subarray(48, 67),
        hexToBytes("68DD0C3A243523BD2971CD2D530E712B2C53BE")
    ));

    test("#3", () => performTest(
        kalyna256,
        IV256,
        alphabet.subarray(64, 145),
        hexToBytes("B62F7F144A8C6772E693A96890F064C3F06831BF743F5B0DD061067F3D22877331AA6A99D939F05B7550E9402BD1615CC7B2D4A167E83EC0D8A894F92C72E176F3880B61C311D69CE1210C59184E818E19")
    ));

    test("#4", () => performTest(
        kalyna256_512,
        IV256_512,
        alphabet.subarray(96, 177),
        hexToBytes("0008F28A82D2D01D23BFB2F8BB4F06D8FE73BA4F48A2977585570ED3818323A668883C9DCFF610CC7E3EA5C025FBBC5CA6520F8F11CA35CEB9B07031E6DBFABE39001E9A3CC0A24BBC565939592B4DEDBD")
    ));

    test("#5", () => performTest(
        kalyna512,
        IV512,
        alphabet.subarray(128, 225),
        hexToBytes(
            "CAA761980599B3ED2E945C41891BAD95F72B11C73ED26536A6847458BC76C827357156B4B3FE0DC1877F5B9F17B866C3" +
            "7B21D89531DB48007D05DEC928B06766C014BB9080385EDF0677E48A0A39B5E7489E28E82FFFD1F84694F17296CB7016" +
            "56"
        )
    ));
});