import { test, expect } from "bun:test";
import { type Kalyna, Kalyna128, Kalyna128_256, Kalyna256, Kalyna256_512, Kalyna512 } from ".";
import { hexToBytes, type TRet } from "@noble/hashes/utils.js";
import { IV128, IV128_256, IV256, IV256_512, IV512, KEY128, KEY256, KEY512 } from "../modes/_test_utils.test";

const performTest = (cipher: Kalyna, pt: Uint8Array, ct: Uint8Array) => {
    expect(cipher.encrypt(pt)).toStrictEqual(ct as TRet<Uint8Array>);
    expect(cipher.decrypt(ct)).toStrictEqual(pt as TRet<Uint8Array>);
}

test("[CORE] Kalyna-128/128", () => performTest(
    new Kalyna128(KEY128),
    IV128,
    hexToBytes("81BF1C7D779BAC20E1C9EA39B4D2AD06")
));

test("[CORE] Kalyna-128/256", () => performTest(
    new Kalyna128_256(KEY256),
    IV128_256,
    hexToBytes("58EC3E091000158A1148F7166F334F14")
));

test("[CORE] Kalyna-256/256", () => performTest(
    new Kalyna256(KEY256),
    IV256,
    hexToBytes("F66E3D570EC92135AEDAE323DCBD2A8CA03963EC206A0D5A88385C24617FD92C")
));

test("[CORE] Kalyna-256/512", () => performTest(
    new Kalyna256_512(KEY512),
    IV256_512,
    hexToBytes("606990E9E6B7B67A4BD6D893D72268B78E02C83C3CD7E102FD2E74A8FDFE5DD9")
));

test("[CORE] Kalyna-512/512", () => performTest(
    new Kalyna512(KEY512),
    IV512,
    hexToBytes("4A26E31B811C356AA61DD6CA0596231A67BA8354AA47F3A13E1DEEC320EB56B895D0F417175BAB662FD6F134BB15C86CCB906A26856EFEB7C5BC6472940DD9D9")
));