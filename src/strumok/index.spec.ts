import { describe, test, expect } from "bun:test";
import { Strumok } from ".";
import { hexToBytes } from "@noble/hashes/utils.js";

describe("[CORE] Strumok", () => {
    test("#1", () => {
        const key = hexToBytes("0000000000000000000000000000000000000000000000008000000000000000");
        const iv = new Uint8Array(32);
        const expected = new BigUint64Array([
            0xe442d15345dc66can,
            0xf47d700ecc66408an,
            0xb4cb284b5477e641n,
            0xa2afc9092e4124b0n,
            0x728e5fa26b11a7d9n,
            0xe6a7b9288c68f972n,
            0x70eb3606de8ba44cn,
            0xaced7956bd3e3de7n
        ]);

        const a = new Strumok(key, iv);
        const stream = a.next_stream();
        for(let i = 0; i < expected.length; i++) expect(stream[i]).toStrictEqual(expected[i]);
    });

    test("#2", () => {
        const key = new Uint8Array(32).fill(0xaa);
        const iv = new Uint8Array(32);
        const expected = new BigUint64Array([
            0xa7510b38c7a95d1dn,
            0xcd5ea28a15b8654fn,
            0xc5e2e2771d0373b2n,
            0x98ae829686d5fceen,
            0x45bddf65c523dbb8n,
            0x32a93fcdd950001fn,
            0x752a7fb588af8c51n,
            0x9de92736664212d4n
        ]);

        const a = new Strumok(key, iv);
        const stream = a.next_stream();
        for(let i = 0; i < expected.length; i++) expect(stream[i]).toStrictEqual(expected[i]);
    })

    test("#3", () => {
        const key = hexToBytes("0000000000000000000000000000000000000000000000008000000000000000");
        const iv = hexToBytes("0000000000000001000000000000000200000000000000030000000000000004");
        const expected = new BigUint64Array([
            0xfe44a2508b5a2acdn,
            0xaf355b4ed21d2742n,
            0xdcd7fdd6a57a9e71n,
            0x5d267bd2739fb5ebn,
            0xb22eee96b2832072n,
            0xc7de6a4cdaa9a847n,
            0x72d5da93812680f2n,
            0x4a0acb7e93da2ce0n
        ]);

        const a = new Strumok(key, iv);
        const stream = a.next_stream();
        for(let i = 0; i < expected.length; i++) expect(stream[i]).toStrictEqual(expected[i]);
    });

    test("#4", () => {
        const key = new Uint8Array(32).fill(0xaa);
        const iv = hexToBytes("0000000000000001000000000000000200000000000000030000000000000004");
        const expected = new BigUint64Array([
            0xe6d0efd9cea5abcdn,
            0x1e78ba1a9b0e401en,
            0xbcfbea2c02ba0781n,
            0x1bd375588ae08794n,
            0x5493cf21e114c209n,
            0x66cd5d7cc7d0e69an,
            0xa5cdb9f3380d07fan,
            0x2940d61a4d4e9ce4n,
        ]);

        const a = new Strumok(key, iv);
        const stream = a.next_stream();
        for(let i = 0; i < expected.length; i++) expect(stream[i]).toStrictEqual(expected[i]);
    });

    test("#5", () => {
        const key = hexToBytes("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000");
        const iv = new Uint8Array(32);
        const expected = new BigUint64Array([
            0xf5b9ab51100f8317n,
            0x898ef2086a4af395n,
            0x59571fecb5158d0bn,
            0xb7c45b6744c71fbbn,
            0xff2efcf05d8d8db9n,
            0x7a585871e5c419c0n,
            0x6b5c4691b9125e71n,
            0xa55be7d2b358ec6en
        ]);

        const a = new Strumok(key, iv);
        const stream = a.next_stream();
        for(let i = 0; i < expected.length; i++) expect(stream[i]).toStrictEqual(expected[i]);
    });

    test("#6", () => {
        const key = new Uint8Array(64).fill(0xaa);
        const iv = new Uint8Array(32);
        const expected = new BigUint64Array([
            0xd2a6103c50bd4e04n,
            0xdc6a21af5eb13b73n,
            0xdf4ca6cb07797265n,
            0xf453c253d8d01876n,
            0x039a64dc7a01800cn,
            0x688ce327dccb7e84n,
            0x41e0250b5e526403n,
            0x9936e478aa200f22n
        ]);

        const a = new Strumok(key, iv);
        const stream = a.next_stream();
        for(let i = 0; i < expected.length; i++) expect(stream[i]).toStrictEqual(expected[i]);
    });

    test("#7", () => {
        const key = hexToBytes("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000");
        const iv = hexToBytes("0000000000000001000000000000000200000000000000030000000000000004");
        const expected = new BigUint64Array([
            0xcca12eae8133aaaan,
            0x528d85507ce8501dn,
            0xda83c7fe3e1823f1n,
            0x21416ebf63b71a42n,
            0x26d76d2bf1a625ebn,
            0xeec66ee0cd0b1efcn,
            0x02dd68f338a345a8n,
            0x47538790a5411adbn
        ]);

        const a = new Strumok(key, iv);
        const stream = a.next_stream();
        for(let i = 0; i < expected.length; i++) expect(stream[i]).toStrictEqual(expected[i]);
    });

    test("#8", () => {
        const key = new Uint8Array(64).fill(0xaa);
        const iv = hexToBytes("0000000000000001000000000000000200000000000000030000000000000004");
        const expected = new BigUint64Array([
            0x965648e775c717d5n,
            0xa63c2a7376e92df3n,
            0x0b0eb0bbd47ca267n,
            0xea593d979ae5bd39n,
            0xd773b5e5193cafe1n,
            0xb0a26671d259422bn,
            0x85b2aa326b280156n,
            0x511ace6451435f0cn
        ]);

        const a = new Strumok(key, iv);
        const stream = a.next_stream();
        for(let i = 0; i < expected.length; i++) expect(stream[i]).toStrictEqual(expected[i]);
    });
});