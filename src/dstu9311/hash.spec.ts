import { describe, test, expect } from "bun:test";
import { gost3431195, gost3431195Hmac } from "./hash";
import { hexToBytes, type TRet } from "@noble/hashes/utils.js";

const performTest = (
    input: Uint8Array,
    expected: Uint8Array
) => expect(gost3431195(input)).toStrictEqual(expected as TRet<Uint8Array>);

describe("[CORE] GOST 34.311-95", () => {
    test("#1", () => performTest(
        new Uint8Array(256).fill(0xff),
        hexToBytes(`8df69d0619119294accb7bb73fad2daf46383058aba12b3e718cb27dc14ae94d`)
    ));
});

describe("[HMAC] GOST 34.311-95", () => {
    test("#1", () => expect(gost3431195Hmac(
        hexToBytes("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"),
        hexToBytes("8888888899999999AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEEFFFFFFFF"),
    )).toStrictEqual(hexToBytes("679142781455AC14C7EA384D6F81D967B7AFFBCF39EB9F9E2B2569D43C7AD8B7")));
});