import assert from "node:assert/strict";
import test from "node:test";
import { createCipheriv, createDecipheriv, pbkdf2Sync } from "node:crypto";
import { BACKUP_LIMITS, decryptCase, encryptCase, isEncryptedBackup } from "../src/features/security-workspace/backup.ts";
import { createDemoCase } from "../src/features/security-workspace/fixtures.ts";
import { createCase, parseCase, serializeCase, updateFindingReview } from "../src/features/security-workspace/model.ts";

const passphrase = "Four unrelated words: Žluťoučký 777";
const copy = (value) => structuredClone(value);
const headerOf = ({ schema, kdf, cipher }) => ({ schema, kdf, cipher });
let source, encrypted, envelope;
test.before(async () => {
  source = await createDemoCase();
  encrypted = await encryptCase(source, passphrase);
  envelope = JSON.parse(encrypted);
});

test("encrypted backups round-trip a complete original case without publishing plaintext metadata", async () => {
  assert.deepEqual(await decryptCase(encrypted, passphrase), source);
  assert.equal(isEncryptedBackup(encrypted), true);
  assert.equal(isEncryptedBackup(serializeCase(source)), false);
  for (const secret of [passphrase, source.title, source.scope, source.evidence[0].content])
    assert.equal(encrypted.includes(secret), false);
  assert.equal(envelope.kdf.iterations, 600000);
  assert.equal(envelope.cipher.bits, 256);
  assert.equal(Buffer.from(envelope.kdf.salt, "base64").length, 16);
  assert.equal(Buffer.from(envelope.cipher.iv, "base64").length, 12);
});

test("ciphertext decrypts with an independent AES-GCM and PBKDF2 implementation", () => {
  const material = pbkdf2Sync(passphrase, Buffer.from(envelope.kdf.salt, "base64"), 600000, 32, "sha256");
  const ciphertext = Buffer.from(envelope.ciphertext, "base64");
  const decipher = createDecipheriv("aes-256-gcm", material, Buffer.from(envelope.cipher.iv, "base64"));
  decipher.setAAD(Buffer.from(JSON.stringify(headerOf(envelope))));
  decipher.setAuthTag(ciphertext.subarray(-16));
  const plaintext = Buffer.concat([decipher.update(ciphertext.subarray(0, -16)), decipher.final()]);
  assert.equal(plaintext.toString(), serializeCase(source));
});

test("every backup uses a new random salt and IV", async () => {
  const second = JSON.parse(await encryptCase(source, passphrase));
  assert.notEqual(second.kdf.salt, envelope.kdf.salt);
  assert.notEqual(second.cipher.iv, envelope.cipher.iv);
  assert.notEqual(second.ciphertext, envelope.ciphertext);
});

test("wrong passphrase, ciphertext, salt and IV modifications fail with the same safe message", async () => {
  const errors = [];
  for (const path of [null, ["ciphertext"], ["kdf", "salt"], ["cipher", "iv"]]) {
    const modified = copy(envelope);
    if (path) {
      const target = path.length === 1 ? modified : modified[path[0]];
      const name = path.at(-1);
      const bytes = Buffer.from(target[name], "base64"); bytes[0] ^= 1; target[name] = bytes.toString("base64");
    }
    try { await decryptCase(JSON.stringify(modified), path ? passphrase : "another long incorrect passphrase"); assert.fail("must reject"); }
    catch (error) { errors.push(error.message); }
  }
  assert.equal(new Set(errors).size, 1);
  assert.match(errors[0], /Cannot unlock/);
  assert.equal(errors[0].includes(passphrase), false);
});

test("unsupported parameters, extra fields, duplicate keys and malformed encodings are rejected before deriving keys", async () => {
  const variants = [];
  for (const mutate of [
    e => e.kdf.iterations = 599999, e => e.kdf.iterations = 999999999,
    e => e.kdf.name = "other", e => e.kdf.hash = "SHA-1", e => e.cipher.bits = 128,
    e => e.cipher.name = "AES-CBC", e => e.schema = "relatio.encrypted-case.v2",
    e => e.extra = true, e => e.kdf.extra = true, e => e.cipher.extra = true,
    e => e.kdf.salt = "AA==", e => e.cipher.iv = "!".repeat(16),
    e => e.ciphertext = "AA==", e => e.ciphertext += "\n",
    e => delete e.ciphertext,
  ]) { const value = copy(envelope); mutate(value); variants.push(JSON.stringify(value)); }
  variants.push(encrypted.replace('"schema":', '"schema":"duplicate","schema":'));
  variants.push(" ".repeat(BACKUP_LIMITS.bytes + 1));
  let derivations = 0;
  const original = crypto.subtle.deriveKey;
  crypto.subtle.deriveKey = async () => { derivations++; throw new Error("unexpected derivation"); };
  try { for (const text of variants) await assert.rejects(decryptCase(text, passphrase)); }
  finally { crypto.subtle.deriveKey = original; }
  assert.equal(derivations, 0);
});

test("valid authentication does not bypass case digest or UTF-8 validation", async () => {
  const material = pbkdf2Sync(passphrase, Buffer.from(envelope.kdf.salt, "base64"), 600000, 32, "sha256");
  const invalidCase = copy(source); invalidCase.evidence[0].content += "changed";
  for (const plaintext of [Buffer.from(JSON.stringify(invalidCase)), Buffer.from([0xff]), Buffer.from('{"unexpected":true}')]) {
    const cipher = createCipheriv("aes-256-gcm", material, Buffer.from(envelope.cipher.iv, "base64"));
    cipher.setAAD(Buffer.from(JSON.stringify(headerOf(envelope))));
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
    await assert.rejects(decryptCase(JSON.stringify({ ...envelope, ciphertext: ciphertext.toString("base64") }), passphrase), /Cannot unlock/);
  }
});

test("passphrase bounds and exact spaces are enforced without silent normalization", async () => {
  const empty = createCase("Empty", "Synthetic scope");
  for (const value of ["", "short", " ".repeat(12), "x".repeat(1025), "abcdefghijkl\ud800"])
    await assert.rejects(encryptCase(empty, value), /passphrase/);
  const protectedCase = await encryptCase(empty, "  exact passphrase  ");
  await assert.rejects(decryptCase(protectedCase, "exact passphrase"), /Cannot unlock/);
  assert.deepEqual(await decryptCase(protectedCase, "  exact passphrase  "), empty);
});

test("invalid evidence is rejected before encrypted export and old plaintext remains compatible", async () => {
  const damaged = copy(source); damaged.evidence[0].sha256 = "a".repeat(64);
  await assert.rejects(encryptCase(damaged, passphrase), /digest/);
  assert.deepEqual(await parseCase(serializeCase(source)), source);
});


test("saved finding triage and notes survive encrypted handover exactly", async () => {
  const reviewed = updateFindingReview(source, source.findings[0].id, "resolved", "Synthetic review note: expected activity.");
  assert.deepEqual(await decryptCase(await encryptCase(reviewed, passphrase), passphrase), reviewed);
});
