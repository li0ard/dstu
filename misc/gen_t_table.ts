import { S } from "../src/const";

const MDS_MATRIX = new BigUint64Array([
    0x0101050108060704n,
    0x0401010501080607n,
    0x0704010105010806n,
    0x0607040101050108n,
    0x0806070401010501n,
    0x0108060704010105n,
    0x0501080607040101n,
    0x0105010806070401n,
]);

const gf_multiply = (x: number, y: number): number => {
    let r = 0, i = 0;
    while (i < 8) {
        if ((y & 1) === 1) r ^= x;
        const hbit = x & 0x80;
        x = (x << 1) & 0xFF;
        if (hbit !== 0) x ^= 0x1d; // x^4 + x^3 + x^2 + 1
        y >>>= 1;
        i += 1;
    }
    return r & 0xFF;
}

const generate_t_table = (sboxes: Readonly<Uint8Array[]>) => {
    const table: BigUint64Array[] = [];

    for (let row = 0; row < 8; row++) {
        const rowTable = new BigUint64Array(256);
        for (let byte = 0; byte < 256; byte++) {
            const s = sboxes[row % 4][byte];

            const out: number[] = new Array(8);
            for (let outRow = 0; outRow < 8; outRow++) {
                const mdsCoef = Number((MDS_MATRIX[outRow] >> BigInt(8 * (7 - row))) & 0xFFn);
                out[outRow] = gf_multiply(mdsCoef, s);
            }

            rowTable[byte] = (BigInt(out[7]) << 56n) |
                (BigInt(out[6]) << 48n) |
                (BigInt(out[5]) << 40n) |
                (BigInt(out[4]) << 32n) |
                (BigInt(out[3]) << 24n) |
                (BigInt(out[2]) << 16n) |
                (BigInt(out[1]) << 8n)  |
                BigInt(out[0]);
        }

        table.push(rowTable);
    }

    return table;
}

console.log(generate_t_table(S));