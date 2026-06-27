import { describe, test, expect } from "bun:test"
import { kmac256, kmac384, kmac512 } from "./kmac";
import { hexToBytes } from "@noble/hashes/utils.js";

describe("[KMAC] Kupyna", () => {
    const msg = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e");
    
    test("256 bit", () => {
        const expected = hexToBytes("B60594D56FA79BA210314C72C2495087CCD0A99FC04ACFE2A39EF669925D98EE");
        const key = hexToBytes("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100");
        expect(kmac256(key, msg)).toStrictEqual(expected);
    });

    test("384 bit", () => {
        const expected = hexToBytes("BEBFD8D730336F043ABACB41829E79A4D320AEDDD8D14024D5B805DA70C396FA295C281A38B30AE728A304B3F5AE490E");
        const key = hexToBytes("2f2e2d2c2b2a292827262524232221201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100");
        expect(kmac384(key, msg)).toStrictEqual(expected);
    });

    test("512 bit", () => {
        const expected = hexToBytes("F270043C06A5C37E65D9D791C5FBFB966E5EE709F8F54019C9A55B76CA40B70100579F269CEC24E347A9D864614CF3ABBF6610742E4DB3BD2ABC000387C49D24");
        const key = hexToBytes("3f3e3d3c3b3a393837363534333231302f2e2d2c2b2a292827262524232221201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100");
        expect(kmac512(key, msg)).toStrictEqual(expected);
    });
});