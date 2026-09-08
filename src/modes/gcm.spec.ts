import { describe, test, expect } from "bun:test";
import { gcm } from "./gcm";
import { hexToBytes, type TRet } from "@noble/hashes/utils.js";
import { alphabet, IV128_256, IV256, IV256_512, IV512, kalyna128_256, kalyna256, kalyna256_512, kalyna512 } from "./_test_utils.test";
import type { Cipher } from "../types";

const performTest = (
    cipher: Cipher,
    iv: Uint8Array,
    aad: Uint8Array,
    msg: Uint8Array,
    ct: Uint8Array,
    q = 16
) => {
    const mode = gcm(cipher, iv, q);
    expect(mode.seal(msg, aad)).toStrictEqual(ct as TRet<Uint8Array>);
    expect(mode.open(ct, aad)).toStrictEqual(msg as TRet<Uint8Array>);
}

describe("[MODE] GCM", () => {
    test("#1", () => performTest(
        kalyna128_256,
        IV128_256,
        alphabet.subarray(48,64),
        alphabet.subarray(80,112),
        hexToBytes("FF83F27C6D4EA26101B1986235831406A297940D6C0E695596D612623E0E7CDC3C474281AFEAE4FD6D61E995258747AB")
    ));

    test("#2", () => performTest(
        kalyna256,
        IV256,
        alphabet.subarray(64,96),
        alphabet.subarray(96,160),
        hexToBytes("7EC15C54BB553CB1437BE0EFDD2E810F6058497EBCE4408A08A73FADF3F459D56B0103702D13AB73ACD2EB33A8B5E9CFFF5EB21865A6B499C10C810C4BAEBE801D61B0A3018F6B849CBA20AF1DDDA245B1B296258AC0352A52D3F372E72224CE"),
        32
    ));

    test("#3", () => performTest(
        kalyna256_512,
        IV256_512,
        alphabet.subarray(96,128),
        alphabet.subarray(128,192),
        hexToBytes("3EBDB4584B5169A26FBEBA0295B4223F58D5D8A031F2950A1D7764FAB97BA058E9E2DAB90FF0C519AA88435155A71B7B53BB100F5D20AFFAC0552F5F2813DEE88555FD3D9B02C2325ACA3CC9309D6B4B9AFC697D13BBBFF067198D5D86CB9820"),
        32
    ));

    test("#4", () => performTest(
        kalyna512,
        IV512,
        alphabet.subarray(128,192),
        alphabet.subarray(192),
        hexToBytes("220642D7277D104788CF97B10210984F506435512F7BF153C5CDABFECC10AFB4A2E2FC51F616AF80FFDD0607FAD4F542B8EF0667717CE3EAAA8FBC303CE76C9978A77E5948F5DC05F551486FDBB44898C9AB1BD439D7519841AE31007C09E1B312E5EA5929F952F6A3EEF5CBEAEF262B8EC1884DFCF4BAAF7B5C9291A22489E1"),
        64
    ));
});