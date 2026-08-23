import { describe, test, expect } from "bun:test";
import { Strumok } from ".";
import { hexToBytes } from "@noble/hashes/utils.js";

const proceedTest = (key: Uint8Array, iv: Uint8Array, expected: Uint8Array) => {
    const cipher = new Strumok(key, iv);
    expect(cipher.next_stream().subarray(0, expected.length)).toStrictEqual(expected);
}

const k1 = hexToBytes("0000000000000000000000000000000000000000000000008000000000000000");
const k2 = new Uint8Array(32).fill(0xaa);
const k3 = hexToBytes("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000");
const k4 = new Uint8Array(64).fill(0xaa);

const iv1 = new Uint8Array(32);
const iv2 = hexToBytes("0000000000000001000000000000000200000000000000030000000000000004");

describe("[CORE] Strumok", () => {
    // D.1.1.1
    test("#1", () => proceedTest(
        k1,
        iv1,
        hexToBytes("e442d15345dc66caf47d700ecc66408ab4cb284b5477e641a2afc9092e4124b0728e5fa26b11a7d9e6a7b9288c68f97270eb3606de8ba44caced7956bd3e3de7")
    ));

    // D.1.1.2
    test("#2", () => proceedTest(
        k2,
        iv1,
        hexToBytes("a7510b38c7a95d1dcd5ea28a15b8654fc5e2e2771d0373b298ae829686d5fcee45bddf65c523dbb832a93fcdd950001f752a7fb588af8c519de92736664212d4")
    ));

    // D.1.1.3
    test("#3", () => proceedTest(
        k1,
        iv2,
        hexToBytes("fe44a2508b5a2acdaf355b4ed21d2742dcd7fdd6a57a9e715d267bd2739fb5ebb22eee96b2832072c7de6a4cdaa9a84772d5da93812680f24a0acb7e93da2ce0")
    ));

    // D.1.1.4
    test("#4", () => proceedTest(
        k2,
        iv2,
        hexToBytes("e6d0efd9cea5abcd1e78ba1a9b0e401ebcfbea2c02ba07811bd375588ae087945493cf21e114c20966cd5d7cc7d0e69aa5cdb9f3380d07fa2940d61a4d4e9ce4")
    ));

    // D.2.1.1
    test("#5", () => proceedTest(
        k3,
        iv1,
        hexToBytes("f5b9ab51100f8317898ef2086a4af39559571fecb5158d0bb7c45b6744c71fbbff2efcf05d8d8db97a585871e5c419c06b5c4691b9125e71a55be7d2b358ec6e")
    ));

    // D.2.1.2
    test("#6", () => proceedTest(
        k4,
        iv1,
        hexToBytes("d2a6103c50bd4e04dc6a21af5eb13b73df4ca6cb07797265f453c253d8d01876039a64dc7a01800c688ce327dccb7e8441e0250b5e5264039936e478aa200f22")
    ));

    // D.2.1.3
    test("#7", () => proceedTest(
        k3,
        iv2,
        hexToBytes("cca12eae8133aaaa528d85507ce8501dda83c7fe3e1823f121416ebf63b71a4226d76d2bf1a625ebeec66ee0cd0b1efc02dd68f338a345a847538790a5411adb")
    ));

    // D.2.1.4
    test("#8", () => proceedTest(
        k4,
        iv2,
        hexToBytes("965648e775c717d5a63c2a7376e92df30b0eb0bbd47ca267ea593d979ae5bd39d773b5e5193cafe1b0a26671d259422b85b2aa326b280156511ace6451435f0c")
    ));
});