/* wasm/test.js - Node harness for the browser playground's wasm32 API.
 *
 * Run from the repository root: node wasm/test.js
 * Known vectors come from test_tea_native.c; entropy cases from
 * test_cbm_decode.c; diff range cases from test_cbm_diff.c (context 0).
 */
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const WASM_PATH = path.join(__dirname, "playground.wasm");
const KEY = "1a2b3c4d5e6fTENG";

async function load() {
  if (!fs.existsSync(WASM_PATH)) {
    throw new Error(`built artifact missing: ${WASM_PATH} (see docs/wasm-playground.md)`);
  }
  const bytes = fs.readFileSync(WASM_PATH);
  const result = await WebAssembly.instantiate(bytes, {});
  const imports = WebAssembly.Module.imports(result.module);
  assert.equal(imports.length, 0, "module must be self-contained (no libc imports)");
  return result.instance.exports;
}

function hex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function u32(memory, ptr, index) {
  return new DataView(memory.buffer).getUint32(ptr + index * 4, true);
}

function run(exports) {
  const mem = exports.memory;
  const cap = exports.wasm_cap();
  const a = exports.wasm_buf_a();
  const b = exports.wasm_buf_b();
  const keyPtr = exports.wasm_key();
  const blob = exports.wasm_string_blob();
  const refs = exports.wasm_string_refs();
  const ranges = exports.wasm_diff_ranges();
  const tests = [];
  const test = (name, fn) => tests.push([name, fn]);

  function putKey() {
    new Uint8Array(mem.buffer, keyPtr, 16).set(Buffer.from(KEY, "ascii"));
  }
  function copyTo(dst, src) {
    new Uint8Array(mem.buffer, dst, src.length).set(src);
  }
  function take(src, len) {
    return Uint8Array.from(new Uint8Array(mem.buffer, src, len));
  }

  test("static memory cap is 256 KiB and regions are distinct", () => {
    assert.equal(cap, 262144);
    assert.equal(exports.wasm_blob_cap(), 65536);
    assert.equal(exports.wasm_string_max(), 256);
    assert.equal(exports.wasm_diff_max(), 4096);
    for (const ptr of [a, b, blob, refs, ranges, keyPtr]) {
      assert.ok(ptr >= 0 && ptr + 16 <= mem.buffer.byteLength, `bad pointer ${ptr}`);
    }
    assert.notEqual(a, b);
  });

  const vectors = [
    {
      name: "A (8 zero bytes)",
      input: new Uint8Array(8),
      golden: "e66254b5da09fb31",
    },
    {
      name: "B (bytes 0..31)",
      input: Uint8Array.from({ length: 32 }, (_, i) => i),
      golden:
        "3dd24f1e5c7d940ef690cfcc84ddff02660d74c782b22e1e4015059980c24f01",
    },
    {
      name: "C (15 bytes, odd)",
      input: Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
      golden: "1b787ed12c571f48090a0b0c0d0e0f",
    },
  ];

  for (const v of vectors) {
    test(`encrypt matches C golden vector ${v.name}`, () => {
      putKey();
      copyTo(a, v.input);
      assert.equal(exports.tea_encrypt(a, v.input.length, keyPtr, 16), 0);
      assert.equal(hex(take(a, v.input.length)), v.golden);
    });
    test(`decrypt of C golden vector ${v.name} returns plaintext`, () => {
      putKey();
      copyTo(a, Buffer.from(v.golden, "hex"));
      assert.equal(exports.tea_decrypt(a, v.input.length, keyPtr, 16), 0);
      assert.deepEqual(take(a, v.input.length), v.input);
    });
    test(`decrypt -> encrypt identity ${v.name}`, () => {
      putKey();
      copyTo(a, Buffer.from(v.golden, "hex"));
      assert.equal(exports.tea_decrypt(a, v.input.length, keyPtr, 16), 0);
      assert.deepEqual(take(a, v.input.length), v.input);
      assert.equal(exports.tea_encrypt(a, v.input.length, keyPtr, 16), 0);
      assert.equal(hex(take(a, v.input.length)), v.golden);
    });
  }

  test("invalid key length is rejected without changing the buffer", () => {
    copyTo(a, Buffer.from(vectors[0].golden, "hex"));
    const before = take(a, 8);
    assert.notEqual(exports.tea_decrypt(a, 8, keyPtr, 15), 0);
    assert.deepEqual(take(a, 8), before);
  });

  test("oversized input is rejected before any buffer read", () => {
    putKey();
    assert.equal(exports.tea_encrypt(a, cap + 1, keyPtr, 16), -2);
    assert.equal(exports.entropy_estimate(a, cap + 1), -1);
  });

  test("entropy of 1024 zero bytes is exactly 0", () => {
    copyTo(a, new Uint8Array(1024));
    assert.equal(exports.entropy_estimate(a, 1024), 0);
  });

  test("entropy of bytes 0..255 once each is 8 +/- 1e-9", () => {
    copyTo(a, Uint8Array.from({ length: 256 }, (_, i) => i));
    assert.ok(Math.abs(exports.entropy_estimate(a, 256) - 8) < 1e-9);
  });

  test("entropy of a 4-symbol uniform body is 2 +/- 1e-9", () => {
    copyTo(a, Uint8Array.from({ length: 256 }, (_, i) => [10, 20, 30, 40][i % 4]));
    assert.ok(Math.abs(exports.entropy_estimate(a, 256) - 2) < 1e-9);
  });

  test("empty input has zero entropy", () => {
    assert.equal(exports.entropy_estimate(a, 0), 0);
  });

  test("printable scan lists runs of at least 4 bytes with correct offsets", () => {
    const input = new Uint8Array(64);
    let at = 0;
    const put = (s) => {
      for (const ch of s) input[at++] = ch.charCodeAt(0);
    };
    put("abc");
    input[at++] = 0;
    put("hello world");
    input[at++] = 1;
    put("XY");
    input[at++] = 0;
    put("CBM container ready!");
    input[at++] = 0;
    put("@@");
    copyTo(a, input);

    const n = exports.scan_strings(
      a,
      at,
      blob,
      exports.wasm_blob_cap(),
      refs,
      exports.wasm_string_max()
    );
    assert.equal(n, 2);
    const expected = [
      [4, "hello world"],
      [19, "CBM container ready!"],
    ];
    for (let i = 0; i < n; i++) {
      const source = u32(mem, refs, i * 3);
      const blobOff = u32(mem, refs, i * 3 + 1);
      const len = u32(mem, refs, i * 3 + 2);
      const text = Buffer.from(new Uint8Array(mem.buffer, blob + blobOff, len)).toString("ascii");
      assert.deepEqual([source, text], expected[i]);
      assert.equal(u32(mem, refs, i * 3 + 2), expected[i][1].length);
    }
  });

  test("printable scan rejects an input over the cap", () => {
    assert.equal(
      exports.scan_strings(a, cap + 1, blob, exports.wasm_blob_cap(), refs, 256),
      -2
    );
  });

  test("diff of identical bodies has no ranges", () => {
    const body = Uint8Array.from({ length: 16 }, (_, i) => i);
    copyTo(a, body);
    copyTo(b, body);
    assert.equal(exports.diff_two(a, 16, b, 16, ranges, 8), 0);
  });

  test("diff of one changed byte matches the C range vector", () => {
    const body = Uint8Array.from({ length: 16 }, (_, i) => 97 + i);
    const changed = Uint8Array.from(body);
    changed[10] ^= 1;
    copyTo(a, body);
    copyTo(b, changed);
    const n = exports.diff_two(a, 16, b, 16, ranges, 8);
    assert.equal(n, 1);
    assert.deepEqual(
      [u32(mem, ranges, 0), u32(mem, ranges, 1), u32(mem, ranges, 2)],
      [10, 1, 1]
    );
  });

  test("diff with context 0 keeps non-touching changes separate", () => {
    const body = new Uint8Array(32).fill(65);
    const changed = Uint8Array.from(body);
    changed[10] ^= 1;
    changed[12] ^= 1;
    changed[14] ^= 1;
    copyTo(a, body);
    copyTo(b, changed);
    const n = exports.diff_two(a, 32, b, 32, ranges, 8);
    assert.equal(n, 3);
    for (let i = 0; i < n; i++) {
      assert.deepEqual(
        [u32(mem, ranges, i * 3), u32(mem, ranges, i * 3 + 2)],
        [10 + i * 2, 1]
      );
    }
  });

  test("diff of a length difference appends a trailing range", () => {
    copyTo(a, Uint8Array.from([0, 1, 2]));
    copyTo(b, Uint8Array.from([0, 1, 2, 3, 4]));
    const n = exports.diff_two(a, 3, b, 5, ranges, 8);
    assert.equal(n, 1);
    assert.deepEqual(
      [u32(mem, ranges, 0), u32(mem, ranges, 1), u32(mem, ranges, 2)],
      [3, 2, 2]
    );
  });

  test("diff caps writes at max_ranges", () => {
    const body = new Uint8Array(32).fill(65);
    const changed = Uint8Array.from(body);
    changed[10] ^= 1;
    changed[12] ^= 1;
    changed[14] ^= 1;
    copyTo(a, body);
    copyTo(b, changed);
    assert.equal(exports.diff_two(a, 32, b, 32, ranges, 2), 2);
    assert.equal(u32(mem, ranges, 3), 12);
  });

  test("diff rejects negative lengths", () => {
    assert.equal(exports.diff_two(a, -1, b, 1, ranges, 8), -1);
  });

  let passed = 0;
  let failed = 0;
  for (const [name, fn] of tests) {
    try {
      fn();
      passed++;
      console.log(`PASS ${name}`);
    } catch (err) {
      failed++;
      console.error(`FAIL ${name}\n  ${err.message}`);
    }
  }
  console.log(`Results: ${passed} passed, ${failed} failed`);
  if (failed) process.exitCode = 1;
}

load()
  .then(run)
  .catch((err) => {
    console.error(`FAIL harness: ${err.message}`);
    process.exitCode = 1;
  });
