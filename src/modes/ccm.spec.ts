import { describe, test, expect } from "bun:test";
import { ccm } from "./ccm";
import { hexToBytes, type TRet } from "@noble/hashes/utils.js";
import type { Cipher } from "../types";
import { alphabet, IV128, IV128_256, IV256, IV256_512, IV512, kalyna128, kalyna128_256, kalyna256, kalyna256_512, kalyna512 } from "./_test_utils.test";

const performTest = (
    cipher: Cipher,
    iv: Uint8Array,
    aad: Uint8Array,
    msg: Uint8Array,
    ct: Uint8Array,
    q?: number,
    Nb?: number
) => {
    const mode = ccm(cipher, iv, q, Nb);
    expect(mode.seal(msg, aad)).toStrictEqual(ct as TRet<Uint8Array>);
    expect(mode.open(ct, aad)).toStrictEqual(msg as TRet<Uint8Array>);
}

describe("[MODE] CCM", () => {
    test("#1", () => performTest(
        kalyna128,
        IV128,
        alphabet.subarray(32, 48),
        alphabet.subarray(48, 64),
        hexToBytes("B91A7B8790BBCFCFE65D04E5538E98E2704454C9DD39ADACE0B19D03F6AAB07E")
    ));

    test("#2", () => performTest(
        kalyna128_256,
        IV128_256,
        alphabet.subarray(48, 60),
        alphabet.subarray(64, 79),
        hexToBytes("EF93E26C7D5EB27111A188722593043585DF9998FE26308ACBA4FC0EB5F2C7")
    ));

    test("#3", () => performTest(
        kalyna256,
        IV256,
        alphabet.subarray(64, 96),
        alphabet.subarray(96, 160),
        hexToBytes("7EC15C54BB553CB1437BE0EFDD2E810F6058497EBCE4408A08A73FADF3F459D56B0103702D13AB73ACD2EB33A8B5E9CFFF5EB21865A6B499C10C810C4BAEBE809C48AD90A9E12A68380EF1C1B7C83EE1")
    ));

    test("#4", () => performTest(
        kalyna256_512,
        IV256_512,
        alphabet.subarray(96, 128),
        alphabet.subarray(128, 192),
        hexToBytes("3EBDB4584B5169A26FBEBA0295B4223F58D5D8A031F2950A1D7764FAB97BA058E9E2DAB90FF0C519AA88435155A71B7B53BB100F5D20AFFAC0552F5F2813DEE8DD3653491737B9615A5CCD83DB32F1E479BF227C050325BBBFF60BCA9558D7FE"),
        32, 6
    ));

    test("#5", () => performTest(
        kalyna512,
        IV512,
        alphabet.subarray(128, 192),
        alphabet.subarray(192),
        hexToBytes("220642D7277D104788CF97B10210984F506435512F7BF153C5CDABFECC10AFB4A2E2FC51F616AF80FFDD0607FAD4F542B8EF0667717CE3EAAA8FBC303CE76C99BD8F80CE149143C04FC2490272A31B029DDADA82F055FE4ABEF452A7D438B21E59C1D8B3DD4606BAD66A6F36300EF3CE0E5F3BB59F11416E80B7FC5A8E8B057A"),
        64, 8
    ));
});