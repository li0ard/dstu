import { describe, test, expect } from "bun:test";
import { copyBytes, hexToBytes, type TRet } from "@noble/hashes/utils.js";
import { keywrap } from "./keywrap";
import { IV256, KEY256 } from "./modes/_test_utils.test";

const performTest = (
    key: Uint8Array,
    iv: Uint8Array,
    pt: Uint8Array,
    ct: Uint8Array
) => {
    const mode = keywrap(key);
    expect(mode.wrap(pt, iv)).toStrictEqual(ct as TRet<Uint8Array>);
    expect(mode.unwrap(ct)).toStrictEqual(pt as TRet<Uint8Array>);
}

test("Key wrap", () => performTest(
    KEY256,
    IV256,
    copyBytes(KEY256).reverse(),
    hexToBytes("7B74FCBF080464F81BF8EAF10621B624A4F053446128396CC2F529BD3E2078DAD6BC0B4C5AAF47711D1BE5CDC0D4849EC50DC4484F7CF393BC7F5F3E8A8728CA13DDAEE30C297D6C82C8751E533A3E7591E7D400B89AE64237F692EC892333CD")
));