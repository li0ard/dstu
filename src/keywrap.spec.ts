import { describe, test, expect } from "bun:test";
import { copyBytes, hexToBytes, type TRet } from "@noble/hashes/utils.js";
import { keyWrap } from "./keywrap";
import { IV256, KEY256 } from "./modes/_test_utils.test";

const performTest = (
    key: Uint8Array,
    iv: Uint8Array,
    pt: Uint8Array,
    ct: Uint8Array,
    useDstu9311?: boolean
) => {
    const mode = keyWrap(key, useDstu9311);
    expect(mode.wrap(pt, iv)).toStrictEqual(ct as TRet<Uint8Array>);
    expect(mode.unwrap(ct)).toStrictEqual(pt as TRet<Uint8Array>);
}

describe("Key wrap", () => {
    test("Kalyna", () => performTest(
        KEY256,
        IV256,
        copyBytes(KEY256).reverse(),
        hexToBytes("7B74FCBF080464F81BF8EAF10621B624A4F053446128396CC2F529BD3E2078DAD6BC0B4C5AAF47711D1BE5CDC0D4849EC50DC4484F7CF393BC7F5F3E8A8728CA13DDAEE30C297D6C82C8751E533A3E7591E7D400B89AE64237F692EC892333CD")
    ));

    test("DSTU 9311:2024", () => performTest(
        hexToBytes("01000000010000000100000001000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
        hexToBytes("F477DA7AA6424A88"),
        hexToBytes("01020304010203040102030401020304F1F2F3F4F5F6F7F8F1F2F3F4F5F6F7F8"),
        hexToBytes("52A513F1B4172CA6B5F1B8A03CA9A4E0ACB6E00E11E5E9BCDD446222EB97238DC3E4E24D2EC03E05A568EC51"),
        true
    ));
});