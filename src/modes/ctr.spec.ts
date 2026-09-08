import { describe, test, expect } from "bun:test";
import { ctr } from "./ctr";
import { hexToBytes, type TRet } from "@noble/hashes/utils.js";
import { alphabet, IV128, IV128_256, IV256, IV256_512, IV512, kalyna128, kalyna128_256, kalyna256, kalyna256_512, kalyna512 } from "./_test_utils.test";
import type { Cipher } from "../types";

const performTest = (
    cipher: Cipher,
    iv: Uint8Array,
    pt: Uint8Array,
    ct: Uint8Array,
) => {
    const mode = ctr(cipher, iv);
    expect(mode.crypt(pt)).toStrictEqual(ct as TRet<Uint8Array>);
    expect(mode.crypt(ct)).toStrictEqual(pt as TRet<Uint8Array>);
}

describe("[MODE] CTR", () => {
    test("#1", () => performTest(
        kalyna128,
        IV128,
        alphabet.subarray(32, 73),
        hexToBytes("A90A6B9780ABDFDFF64D14F5439E88F266DC50EDD341528DD5E698E2F000CE21F872DAF9FE1811844A")
    ));

    test("#2", () => performTest(
        kalyna128_256,
        IV128_256,
        alphabet.subarray(48, 80),
        hexToBytes("9FE3921C0D2EC20161D1F80255E3746682B7B42D4C2E4975B6F632421E2E5CFC")
    ));

    test("#3", () => performTest(
        kalyna256,
        IV256,
        alphabet.subarray(64,144),
        hexToBytes("5EE17C749B751C91635BC0CFFD0EA12F4078695E9CC460AA28871F8DD3D479F58BE1E390CDF34B934C320BD34855092F1FBE52F88546547921EC61ECAB4E5E6086711EA79DDBA33473E93005EECABF6E")
    ));

    test("#4", () => performTest(
        kalyna256_512,
        IV256_512,
        alphabet.subarray(96,176),
        hexToBytes("DE5D54B8ABB189428F5E5AE27554C2DFB8353840D11275EAFD97841A599B40B8C9C2FA992FD0E5398AA8637175873B5B739B302F7D008FDAE0750F7F0833FEC8EFD851D8DBB62A93673CE7009FD2D96C")
    ));

    test("#5", () => performTest(
        kalyna512,
        IV512,
        alphabet.subarray(128,224),
        hexToBytes("62460297673D5007C88FD7F14250D80F102475116F3BB113858DEBBE8C50EFF4E2A2BC11B656EFC0BF9D4647BA94B502F8AF4627313CA3AAEACFFC707CA72CD9A95B1CCE08DC4DD4A8EA0765986103C21B7C0DB0FBB602F279B1A00D5E4FFA18")
    ));
});