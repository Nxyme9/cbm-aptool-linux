/* wasm/app.js - hand-written UI for the local WASM playground.
 * No framework, no server, no install. All file bytes stay in this tab.
 */
"use strict";

const $ = (id) => document.getElementById(id);
const CAP_HINT = "262144 bytes (256 KiB)";
const REQUIRED = [
  "memory", "wasm_cap", "wasm_blob_cap", "wasm_string_max", "wasm_diff_max",
  "wasm_buf_a", "wasm_buf_b", "wasm_key", "wasm_string_blob",
  "wasm_string_refs", "wasm_diff_ranges", "tea_encrypt", "tea_decrypt",
  "entropy_estimate", "scan_strings", "diff_two",
];
const ROWS_PER_PAGE = 32;
const BYTES_PER_ROW = 16;

let api = null;
let display = null;        // Uint8Array currently shown in the hex viewer
let other = null;          // second file, raw bytes
let sourceName = "modified-container.bin";
let encrypted = true;      // first file is assumed to be an encrypted container
let page = 0;
let diffResult = [];
let asciiCells = [];

function status(text) { $("status").textContent = text; }
function error(text) { $("error").textContent = text; }

function ensureApi() {
  if (!api) { error("Load playground.wasm first (see the module section above)."); return false; }
  return true;
}

function region(ptr, len) {
  return new Uint8Array(api.memory.buffer, ptr, len);
}

function syncA() {
  if (!display || !ensureApi()) return false;
  region(api.wasm_buf_a(), display.length).set(display);
  return true;
}

async function instantiate(bytes) {
  try {
    const result = await WebAssembly.instantiate(bytes, {});
    const exports = result.instance.exports;
    const missing = REQUIRED.filter((name) => !exports[name]);
    if (missing.length) throw new Error("module is missing exports: " + missing.join(", "));
    api = exports;
    status("WASM module ready. Static file cap: " + CAP_HINT + ".");
    error("");
    $("wasmHint").textContent = "Module loaded. All processing now happens locally in this tab.";
  } catch (err) {
    error("Could not load the WASM module: " + err.message);
  }
}

async function boot() {
  try {
    const response = await fetch(new URL("playground.wasm", document.baseURI));
    if (!response.ok) throw new Error("HTTP " + response.status);
    await instantiate(await response.arrayBuffer());
  } catch (err) {
    status("Fetch blocked. Choose playground.wasm in the module section above.");
    error("Automatic load failed (" + err.message + "). Local file:// pages need the manual picker; no file data was sent anywhere.");
  }
}

function hexOffset(n) {
  return "0x" + n.toString(16).toUpperCase().padStart(8, "0");
}

function isPrintable(c) { return c >= 0x20 && c <= 0x7e; }

function asciiOf(offset, length) {
  let out = "";
  const end = Math.min(display.length, offset + length);
  for (let i = offset; i < end; i++) {
    out += isPrintable(display[i]) ? String.fromCharCode(display[i]) : ".";
  }
  return out;
}

function renderStats(entropy, printableCount, stringCount) {
  const len = display.length;
  $("statSize").textContent = len.toLocaleString() + " bytes";
  $("statState").textContent = encrypted ? "encrypted (assumed)" : "decrypted (displayed bytes)";
  $("statPrintable").textContent = len
    ? ((printableCount / len) * 100).toFixed(1) + "% (" + printableCount + " bytes)"
    : "—";
  $("statStrings").textContent = String(stringCount);
  $("entropyText").textContent = "Entropy: " + entropy.toFixed(6) +
    " bits per byte out of 8 (" + ((entropy / 8) * 100).toFixed(1) + "% of maximum)";
  $("entropyFill").style.width = Math.max(0, Math.min(100, (entropy / 8) * 100)) + "%";
}

function renderStrings() {
  const list = $("strings");
  list.replaceChildren();
  if (!display) { list.append(li("No file loaded.")); return; }
  if (!syncA()) return;
  const refsPtr = api.wasm_string_refs();
  const view = new DataView(api.memory.buffer);
  const count = api.scan_strings(
    api.wasm_buf_a(), display.length,
    api.wasm_string_blob(), api.wasm_blob_cap(),
    refsPtr, api.wasm_string_max()
  );
  const printableCount = display.reduce((n, c) => n + (isPrintable(c) ? 1 : 0), 0);
  const entropy = api.entropy_estimate(api.wasm_buf_a(), display.length);
  if (count < 0) {
    error("String scan could not fit the results in the static buffer (code " + count + ").");
  } else if (count === 0) {
    list.append(li("No printable runs of length 4 or more."));
  } else {
    for (let i = 0; i < count; i++) {
      const source = view.getUint32(refsPtr + i * 12, true);
      const blobOff = view.getUint32(refsPtr + i * 12 + 4, true);
      const len = view.getUint32(refsPtr + i * 12 + 8, true);
      const text = new TextDecoder("utf-8").decode(region(api.wasm_string_blob() + blobOff, len));
      list.append(li(hexOffset(source) + "  " + text));
    }
  }
  renderStats(entropy, printableCount, Math.max(0, count));
}

function li(text) {
  const node = document.createElement("li");
  node.textContent = text;
  return node;
}

function renderHex() {
  const body = $("hexBody");
  body.replaceChildren();
  asciiCells = [];
  if (!display) {
    $("pageLabel").textContent = "no file";
    return;
  }
  const totalRows = Math.ceil(display.length / BYTES_PER_ROW);
  const firstRow = Math.min(page * ROWS_PER_PAGE, Math.max(0, totalRows - 1));
  const lastRow = Math.min(firstRow + ROWS_PER_PAGE, totalRows);
  $("pageLabel").textContent = "rows " + (firstRow + 1) + "–" + lastRow + " of " + totalRows;

  for (let row = firstRow; row < lastRow; row++) {
    const tr = document.createElement("tr");
    const offCell = document.createElement("th");
    offCell.scope = "row";
    offCell.textContent = hexOffset(row * BYTES_PER_ROW);
    tr.append(offCell);

    const hexCell = document.createElement("td");
    hexCell.className = "hex";
    for (let col = 0; col < BYTES_PER_ROW; col++) {
      const offset = row * BYTES_PER_ROW + col;
      if (offset >= display.length) { hexCell.append(document.createTextNode("   ")); continue; }
      const input = document.createElement("input");
      input.type = "text";
      input.size = 2;
      input.maxLength = 2;
      input.className = "byte";
      input.value = display[offset].toString(16).padStart(2, "0");
      input.setAttribute("aria-label", "Byte at offset " + hexOffset(offset) + " in hexadecimal");
      input.addEventListener("change", () => {
        const value = input.value.trim().toLowerCase();
        if (!/^[0-9a-f]{2}$/.test(value)) {
          input.value = display[offset].toString(16).padStart(2, "0");
          error("Invalid hex byte at " + hexOffset(offset) + "; enter exactly two hex digits.");
          return;
        }
        display[offset] = parseInt(value, 16);
        error("");
        asciiCells[row].textContent = asciiOf(row * BYTES_PER_ROW, BYTES_PER_ROW);
        syncA();
        renderStrings();
      });
      hexCell.append(input);
    }
    tr.append(hexCell);

    const asciiCell = document.createElement("td");
    asciiCell.className = "ascii";
    asciiCell.textContent = asciiOf(row * BYTES_PER_ROW, BYTES_PER_ROW);
    asciiCells[row] = asciiCell;
    tr.append(asciiCell);
    body.append(tr);
  }
}

function analyze() {
  if (!display || !ensureApi()) return;
  syncA();
  renderStrings();
  renderHex();
}

async function loadFirst(file) {
  if (!ensureApi()) return;
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (bytes.length > api.wasm_cap()) {
    error("Rejected " + file.name + ": " + bytes.length + " bytes exceeds the " + CAP_HINT +
      " static-memory cap. No bytes were copied into wasm memory.");
    return;
  }
  display = Uint8Array.from(bytes);
  sourceName = file.name || "modified-container.bin";
  encrypted = true;
  other = null;
  diffResult = [];
  page = 0;
  error("");
  status("Loaded " + file.name + " (" + bytes.length + " bytes). Use Decrypt to view the container body.");
  $("diffList").replaceChildren(li("No comparison yet."));
  analyze();
}

async function loadSecond(file) {
  if (!ensureApi()) return;
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (bytes.length > api.wasm_cap()) {
    error("Rejected " + file.name + ": " + bytes.length + " bytes exceeds the " + CAP_HINT +
      " static-memory cap.");
    return;
  }
  other = Uint8Array.from(bytes);
  status("Second file loaded (" + bytes.length + " bytes). Press Compare files.");
}

function writeKey() {
  const key = $("key").value;
  const bytes = new TextEncoder().encode(key);
  if (bytes.length !== 16) {
    error("The key must be exactly 16 ASCII characters (got " + bytes.length + " UTF-8 bytes).");
    return false;
  }
  region(api.wasm_key(), 16).set(bytes);
  return true;
}

function crypt(decrypt) {
  if (!display || !ensureApi() || !syncA() || !writeKey()) return;
  const rc = decrypt
    ? api.tea_decrypt(api.wasm_buf_a(), display.length, api.wasm_key(), 16)
    : api.tea_encrypt(api.wasm_buf_a(), display.length, api.wasm_key(), 16);
  if (rc !== 0) {
    error("Cipher rejected the input (code " + rc + ").");
    return;
  }
  display = Uint8Array.from(region(api.wasm_buf_a(), display.length));
  encrypted = !decrypt;
  error("");
  status(decrypt ? "Decrypted displayed bytes in place." : "Encrypted displayed bytes in place.");
  analyze();
}

function compare() {
  if (!display || !other || !ensureApi()) {
    error("Load both files before comparing.");
    return;
  }
  if (!syncA()) return;
  region(api.wasm_buf_b(), other.length).set(other);
  const n = api.diff_two(
    api.wasm_buf_a(), display.length,
    api.wasm_buf_b(), other.length,
    api.wasm_diff_ranges(), api.wasm_diff_max()
  );
  const list = $("diffList");
  list.replaceChildren();
  if (n < 0) { error("Diff rejected the input (code " + n + ")."); return; }
  diffResult = [];
  let changed = 0;
  for (let i = 0; i < n; i++) {
    const base = i * 12;
    const view = new DataView(api.memory.buffer);
    const range = {
      offset: view.getUint32(api.wasm_diff_ranges() + base, true),
      length: view.getUint32(api.wasm_diff_ranges() + base + 4, true),
      changed: view.getUint32(api.wasm_diff_ranges() + base + 8, true),
    };
    diffResult.push(range);
    changed += range.changed;
    list.append(li(hexOffset(range.offset) + "  length " + range.length +
      "  changed " + range.changed));
  }
  if (!n) list.append(li("Identical bytes; no changed ranges."));
  $("statDiff").textContent = changed + " bytes in " + n + " range(s)";
  status("Compared " + display.length + " displayed bytes with " + other.length + " raw bytes.");
}

function download() {
  if (!display || !ensureApi()) {
    error("Load a file before downloading.");
    return;
  }
  if ($("reencrypt").checked) {
    if (!writeKey()) return;
    if (!syncA()) return;
    const rc = api.tea_encrypt(api.wasm_buf_a(), display.length, api.wasm_key(), 16);
    if (rc !== 0) { error("Cipher rejected the input (code " + rc + ")."); return; }
    display = Uint8Array.from(region(api.wasm_buf_a(), display.length));
    encrypted = true;
    analyze();
  }
  const blob = new Blob([display], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = sourceName.replace(/\.[^.]+$/, "") + ".mod.bin";
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  status("Downloaded " + display.length + " bytes" + (encrypted ? " (encrypted)" : " (as displayed)") + ".");
}

function setupDrop(zone, input, onFile) {
  zone.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") { event.preventDefault(); input.click(); }
  });
  zone.addEventListener("dragover", (event) => { event.preventDefault(); zone.classList.add("dragover"); });
  zone.addEventListener("dragleave", () => zone.classList.remove("dragover"));
  zone.addEventListener("drop", (event) => {
    event.preventDefault();
    zone.classList.remove("dragover");
    const file = event.dataTransfer.files[0];
    if (file) onFile(file);
  });
  input.addEventListener("change", () => {
    const file = input.files[0];
    if (file) onFile(file);
  });
}

setupDrop($("dropA"), $("fileA"), loadFirst);
setupDrop($("dropB"), $("fileB"), loadSecond);
$("decryptBtn").addEventListener("click", () => crypt(true));
$("encryptBtn").addEventListener("click", () => crypt(false));
$("rescanBtn").addEventListener("click", analyze);
$("diffBtn").addEventListener("click", compare);
$("downloadBtn").addEventListener("click", download);
$("prevPage").addEventListener("click", () => {
  if (!display) return;
  page = Math.max(0, page - 1);
  renderHex();
});
$("nextPage").addEventListener("click", () => {
  if (!display) return;
  const totalRows = Math.ceil(display.length / BYTES_PER_ROW);
  page = Math.min(Math.ceil(totalRows / ROWS_PER_PAGE) - 1, page + 1);
  renderHex();
});
$("jumpBtn").addEventListener("click", () => {
  if (!display) return;
  const raw = $("rowJump").value.trim();
  const offset = parseInt(raw, 16);
  if (!Number.isFinite(offset) || offset < 0) {
    error("Enter a non-negative hex offset such as 00000100.");
    return;
  }
  page = Math.floor(Math.floor(offset / BYTES_PER_ROW) / ROWS_PER_PAGE);
  renderHex();
});
$("wasmFile").addEventListener("change", async (event) => {
  const file = event.target.files[0];
  if (file) await instantiate(await file.arrayBuffer());
});

boot();
