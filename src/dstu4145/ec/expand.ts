import type { DSTUShortParameters } from "../const.js";
import { init_onb_parameters } from "./onb.js";
import { createField } from "./math.js";

/** Uncompress point without creating full API curve */
export const expandPoint = (
    xBytes: Uint8Array,
    params: DSTUShortParameters
): { x: Uint8Array; y: Uint8Array } => {
    const { m, ks, a, onb } = params;
    const field = createField(m, ks);
    let converter;
    if(onb) converter = init_onb_parameters(params);

    const bInt = field.fromHexStringOrBytes(params.b);
    const b = (onb && converter) ? converter.onbToPb(bInt) : bInt;
    
    const x = field.fromHexStringOrBytes(xBytes);
    const bit = x.testn(0);
    let xClean = x.clone();
    xClean.setn(0, 0);

    const traceX = onb ? field.traceOnb(xClean) : field.trace(xClean);
    if((traceX === 1 && a === 0) || (traceX === 0 && a === 1))
        xClean.setn(0, 1);

    const xOut = xClean.clone();
    if(onb && converter) xClean = converter.onbToPb(xClean);

    const x2 = field.sqr(xClean);
    const rhs = field.mul(x2, xClean);
    if(a === 1) rhs.ixor(x2);
    rhs.ixor(b);

    const z = field.solve_quad(field.div(rhs, x2));
    const traceZ = field.trace(z);
    if((traceZ === 0 && bit) || (traceZ === 1 && !bit)) field.invBit(z, 0);

    let y = field.mul(z, xClean);
    if (onb && converter) y = converter.pbToOnb(y);

    return {
        x: field.toBytes(xOut, field.LENGTH),
        y: field.toBytes(y, field.LENGTH)
    }
}