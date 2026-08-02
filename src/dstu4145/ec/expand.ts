import type { DSTUShortParameters } from "../const.js";
import { init_onb_parameters } from "./onb.js";
import { createField } from "./math.js";

/** Uncompress point without creating full API curve */
export const expandPoint = (
    xBytes: Uint8Array,
    params: DSTUShortParameters
): { x: Uint8Array; y: Uint8Array } => {
    const { m, ks, a } = params;
    const field = createField(m, ks);
    let converter;
    if(params.onb) converter = init_onb_parameters(params);

    const bInt = field.fromHexStringOrBytes(params.b);

    const b = (params.onb && converter)
        ? converter.onbToPb(bInt)
        : bInt;
    
    const x = field.fromHexStringOrBytes(xBytes);
    const bit = field.testBit(x, 0);
    let xClean = x.clone();
    xClean = field.setBit(xClean, 0, 0);

    const traceX = params.onb ? field.traceOnb(xClean) : field.trace(xClean);
    if ((traceX === 1 && a === 0) || (traceX === 0 && a === 1)) xClean = field.setBit(xClean, 0, 1);

    const qxOut = xClean.clone();
    if (params.onb && converter) xClean = converter.onbToPb(xClean);

    const x2 = field.sqr(xClean);
    let rhs = field.mul(x2, xClean);
    if (a === 1) rhs = rhs.xor(x2);
    if (b) rhs = rhs.xor(b);

    const x2inv = field.invert(x2);
    const c = field.mul(rhs, x2inv);
    let z = field.solve_quad(c);

    const traceZ = field.trace(z);
    if ((traceZ === 0 && bit === 1) || (traceZ === 1 && bit === 0)) {
        const currentBit = field.testBit(z,0);
        z = field.setBit(z, 0, 1 ^ currentBit);
    }

    let y = field.mul(z, xClean);
    if (params.onb && converter) y = converter.pbToOnb(y);

    return {
        x: field.toBytes(qxOut, field.LENGTH),
        y: field.toBytes(y, field.LENGTH)
    }
}