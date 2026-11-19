import { Kalyna } from "../kalyna/index.js";
import type { Cipher } from "../types.js";

export const isKalyna = (cipher: Cipher): cipher is Kalyna => cipher instanceof Kalyna;
export const assertKalyna = (cipher: Cipher) => {
    if(!isKalyna(cipher)) throw new Error("Cipher mode only for Kalyna");
}