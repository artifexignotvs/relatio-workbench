import { parseBoundedJson, parseCase, serializeCase } from "./model.ts";
import { WORKSPACE_LIMITS, type WorkspaceCase } from "./types.ts";

export const BACKUP_LIMITS = Object.freeze({
  iterations: 600000,
  bytes: Math.ceil((WORKSPACE_LIMITS.caseBytes + 16) / 3) * 4 + 2048,
  passphraseMin: 12,
  passphraseMax: 1024,
});
const schema = "relatio.encrypted-case.v1";
const encoder = new TextEncoder();
const failure = "Cannot unlock this backup. Check the passphrase and that the file is complete and unchanged.";
type Row = Record<string, unknown>;
function row(value: unknown, names: string[]): Row {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).length !== names.length ||
      !names.every((name) => Object.hasOwn(value, name)))
    throw new Error("Unsupported encrypted backup structure.");
  return value as Row;
}
function base64(bytes: Uint8Array): string {
  let result = "";
  for (let i = 0; i < bytes.length; i += 8192)
    result += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return btoa(result);
}
function decode(value: unknown, minimum: number, maximum: number): Uint8Array<ArrayBuffer> {
  if (typeof value !== "string" || value.length > Math.ceil(maximum / 3) * 4 ||
      (value.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)))
    throw new Error("Invalid encrypted backup encoding.");
  const bytes = Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
  if (bytes.length < minimum || bytes.length > maximum || base64(bytes) !== value)
    throw new Error("Invalid encrypted backup size or encoding.");
  return bytes;
}
function validateEnvelope(text: string) {
  const value = row(parseBoundedJson(text, BACKUP_LIMITS.bytes), ["schema", "kdf", "cipher", "ciphertext"]);
  const kdf = row(value.kdf, ["name", "hash", "iterations", "salt"]);
  const cipher = row(value.cipher, ["name", "bits", "iv"]);
  // Sumptus ante derivationem clavium stricte terminatur.
  if (value.schema !== schema || kdf.name !== "PBKDF2" || kdf.hash !== "SHA-256" ||
      kdf.iterations !== BACKUP_LIMITS.iterations || cipher.name !== "AES-GCM" || cipher.bits !== 256)
    throw new Error("Unsupported encrypted backup format or parameters.");
  const salt = decode(kdf.salt, 16, 16);
  const iv = decode(cipher.iv, 12, 12);
  const ciphertext = decode(value.ciphertext, 17, WORKSPACE_LIMITS.caseBytes + 16);
  const header = { schema, kdf: { name: "PBKDF2", hash: "SHA-256", iterations: BACKUP_LIMITS.iterations, salt: kdf.salt }, cipher: { name: "AES-GCM", bits: 256, iv: cipher.iv } };
  return { header, salt, iv, ciphertext };
}
function passphraseBytes(passphrase: string): Uint8Array<ArrayBuffer> {
  if (typeof passphrase !== "string" || passphrase.length < BACKUP_LIMITS.passphraseMin ||
      passphrase.length > BACKUP_LIMITS.passphraseMax || !passphrase.trim() ||
      /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(passphrase))
    throw new Error("Use a passphrase of 12 to 1,024 characters. Spaces and letter case are significant.");
  return encoder.encode(passphrase);
}
async function key(passphrase: string, salt: Uint8Array<ArrayBuffer>, usage: KeyUsage) {
  const bytes = passphraseBytes(passphrase);
  try {
    const material = await crypto.subtle.importKey("raw", bytes, "PBKDF2", false, ["deriveKey"]);
    return await crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", iterations: BACKUP_LIMITS.iterations, salt }, material,
      { name: "AES-GCM", length: 256 }, false, [usage]);
  } finally { bytes.fill(0); }
}
export function isEncryptedBackup(text: string): boolean {
  const value = parseBoundedJson(text, BACKUP_LIMITS.bytes);
  if (value && typeof value === "object" && !Array.isArray(value) && Object.hasOwn(value, "schema")) {
    validateEnvelope(text);
    return true;
  }
  return false;
}
export async function encryptCase(value: WorkspaceCase, passphrase: string): Promise<string> {
  const serialized = serializeCase(value);
  await parseCase(serialized);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const header = { schema, kdf: { name: "PBKDF2", hash: "SHA-256", iterations: BACKUP_LIMITS.iterations, salt: base64(salt) }, cipher: { name: "AES-GCM", bits: 256, iv: base64(iv) } };
  const plaintext = encoder.encode(serialized);
  try {
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv, tagLength: 128, additionalData: encoder.encode(JSON.stringify(header)) }, await key(passphrase, salt, "encrypt"), plaintext);
    return JSON.stringify({ ...header, ciphertext: base64(new Uint8Array(ciphertext)) }, null, 2);
  } finally { plaintext.fill(0); }
}
export async function decryptCase(text: string, passphrase: string): Promise<WorkspaceCase> {
  const { header, salt, iv, ciphertext } = validateEnvelope(text);
  const derived = await key(passphrase, salt, "decrypt");
  let plaintext: Uint8Array | undefined;
  try {
    // Caput cum corpore authenticatur; nulla notitia ante probationem redditur.
    plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv, tagLength: 128, additionalData: encoder.encode(JSON.stringify(header)) }, derived, ciphertext));
    return await parseCase(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(plaintext));
  } catch { throw new Error(failure); }
  finally { plaintext?.fill(0); }
}
