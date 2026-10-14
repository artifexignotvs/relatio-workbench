import assert from "node:assert/strict";
import { File } from "node:buffer";
import { createHash } from "node:crypto";
import test from "node:test";

import { evidenceFromFile } from "../src/features/security-workspace/storage.ts";
import { WORKSPACE_LIMITS } from "../src/features/security-workspace/types.ts";

test("text evidence preserves BOM, multibyte characters and original line endings", async () => {
  const source = "\ufeffEvidence: Žluťoučký 🛡️\r\nSecond line\r\n";
  const bytes = Buffer.from(source, "utf8");
  const evidence = await evidenceFromFile(new File([bytes], "sample.txt"));

  assert.equal(evidence.content, source);
  assert.equal(evidence.bytes, bytes.length);
  assert.equal(
    evidence.sha256,
    createHash("sha256").update(bytes).digest("hex"),
  );
  assert.equal(evidence.mediaType, "text/plain");
  assert.equal(evidence.kind, "text");
  assert.equal(Number.isNaN(Date.parse(evidence.addedAt)), false);
  assert.match(evidence.id, /^[0-9a-f-]{36}$/);
});

test("invalid UTF-8 is rejected instead of being silently replaced before hashing", async () => {
  const invalidSequences = [
    [0xff],
    [0xc0, 0xaf],
    [0xed, 0xa0, 0x80],
    [0xe2, 0x82],
  ];
  for (const bytes of invalidSequences) {
    await assert.rejects(
      evidenceFromFile(new File([new Uint8Array(bytes)], "sample.txt")),
      /UTF-8/,
    );
  }
});

test("NUL-containing binary input is rejected even when its bytes decode as UTF-8", async () => {
  await assert.rejects(
    evidenceFromFile(new File([new Uint8Array([0x61, 0, 0x62])], "sample.txt")),
    /Binary evidence/,
  );
});

test("oversized evidence is rejected before reading its body", async () => {
  let read = false;
  const file = {
    name: "oversized.txt",
    size: WORKSPACE_LIMITS.evidenceBytes + 1,
    async arrayBuffer() {
      read = true;
      throw new Error("Body must not be read");
    },
  };

  await assert.rejects(evidenceFromFile(file), /smaller|size limit/);
  assert.equal(read, false);
});

test("the byte boundary is enforced on actual content as well as declared size", async () => {
  const bytes = new Uint8Array(WORKSPACE_LIMITS.evidenceBytes + 1);
  const file = {
    name: "changed.txt",
    size: 1,
    async arrayBuffer() {
      return bytes.buffer;
    },
  };
  await assert.rejects(evidenceFromFile(file), /size limit/);

  const valid = new Uint8Array(WORKSPACE_LIMITS.evidenceBytes).fill(0x61);
  const evidence = await evidenceFromFile(new File([valid], "boundary.txt"));
  assert.equal(evidence.bytes, WORKSPACE_LIMITS.evidenceBytes);
  assert.equal(
    evidence.sha256,
    createHash("sha256").update(valid).digest("hex"),
  );
});

test("empty text is a valid exact-byte evidence item, with independently computed digest", async () => {
  const evidence = await evidenceFromFile(new File([], "empty.txt"));
  assert.equal(evidence.bytes, 0);
  assert.equal(evidence.content, "");
  assert.equal(evidence.sha256, createHash("sha256").update("").digest("hex"));
});

test("HTML-like content stays literal evidence and extension classification never executes or parses it", async () => {
  const content =
    '<img src="https://example.invalid/pixel" onerror="alert(1)">\n[link](javascript:alert(1))';
  const evidence = await evidenceFromFile(new File([content], "capture.JSON"));
  assert.equal(evidence.content, content);
  assert.equal(evidence.kind, "json");
  assert.equal(evidence.mediaType, "application/json");
  assert.equal(
    evidence.sha256,
    createHash("sha256").update(content).digest("hex"),
  );
});

test("evidence names cannot introduce control-character rows and are bounded", async () => {
  const evidence = await evidenceFromFile(
    new File(["sample"], "name\n\r\t\u007f" + "a".repeat(300)),
  );
  assert.equal(/[\u0000-\u001f\u007f]/.test(evidence.name), false);
  assert.equal(evidence.name.length, 200);
});
