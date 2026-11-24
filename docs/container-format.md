# CBM container format — observations, **inferred** readings, and known gaps

**This is not a complete field map.** The vendor serialiser was not recovered.
Every interpretation beyond "these bytes decrypt to these bytes" is marked
**inferred**. No claim is made about field names, record boundaries,
checksums, authenticity, or semantic validity of the decrypted body.

## Evidence base

- `cbm_container.{h,c}` — size constant, header check, HLEN computation,
  TEA encrypt/decrypt dispatch.
- `tea_native.{h,c}` and `tea_crypto.{h,c}` — cipher dispatch; byte-identical
  to the vendor PE oracle on golden vectors (see `ARCHITECTURE.md` §9).
- `cbm_decode.{h,c}` — Shannon entropy and a 64-byte window heuristic.
- `cbm_diff.{h,c}` — context-merged byte diff with locale-independent output.
- `cbm_fuzz.{h,c}` — deterministic corpus generator with identity verification.
- Host-observed containers and synthetic containers produced offline; **no**
  vendor binary or device access is needed to reproduce any claim below.

## 1. Outer container

| Item | Value | Status |
|---|---|---|
| Total size | 85688 bytes (`CBM_CONTAINER_SIZE`) | observed constant |
| Byte 0 | one-byte header; high bit tested by `cbm_check_encrypted` | **inferred**: the high bit means "encrypted"; the remaining seven bits are not interpreted |
| Body start | byte offset 1 (`CBM_HEADER_SIZE`) | **inferred** from the working decrypt path |
| Body length | 85687 bytes (= 85688 − 1) | observed; equals `cbm_compute_hlen(85688)` |
| HLEN formula | `((filesize − 511) & ~7) + 511`, i.e. 85687 at this size | **inferred**: the formula reproduces the body length; it is *not* a body start offset (decrypting a one-byte body would be impossible) |
| Body cipher | TEA variant, 16-byte published key, CBC-like chaining | key/roundtrip observed; "CBC-like" is **inferred** from the PE XOR region `0x45a0ff`–`0x45a177` |
| Odd tail | `floor(len / 8)` whole blocks are transformed; trailing bytes are left untouched by the native core | observed in `tea_native` (85687 mod 8 = 7) |
| Vendor error strings | `File is encrypted!`, `Decrypt Faile!` | observed during RE; meaning **inferred** |

The key `1a2b3c4d5e6fTENG` is a published reverse-engineering artifact, not a
service credential, and is allowlisted in `.gitleaks.toml`. It is disclosed in
the source for protocol reproducibility.

**Authenticity is not claimed.** `decrypt → encrypt` equality proves only that
this cipher is invertible on the bytes we tested, not that a container is
vendor-issued or internally consistent.

## 2. Body observations (**inferred** semantics)

The decrypted 85687-byte body is treated as opaque bytes. The following are
local analysis heuristics, **not** recovered vendor field types:

- **Entropy** (`cbm_decode_entropy`): Shannon entropy in bits/byte from a
  256-entry histogram, printed as fixed-point `%u.%06u` so output is stable
  under any `LC_NUMERIC`.
- **Regions** (`cbm_decode_regions`, `cbm_decode_profile`): non-overlapping
  64-byte windows classified as `constant` (all bytes equal), `string`
  (at least 85% printable ASCII `0x20`–`0x7e`, exact integer comparison), or
  `opaque` (anything else). Adjacent windows of the same kind are merged by
  `cbm_decode_regions`. **Inferred**: these are useful signposts, not vendor
  records; a `string` window does not prove a field is textual.
- **Diff heatmap** (`cbm_diff_print`): changed spans merge when a gap is at
  most `--context` bytes; the heatmap shows printable density per side for
  each range. **Inferred**: density changes are interesting, but no field
  meaning is assigned to them.
- **Header byte preservation**: fuzz copies byte 0 verbatim into every corpus
  file. **Inferred**: the tool does not know what the header means, so it does
  not modify it.

What is **not** known: body field names, offsets of any structured records,
magic values, length fields, checksums/CRCs, compression, versioning, whether
segments are optional, and whether the vendor tool validates any of these.
Do not read the classifier labels as a schema.

## 3. Tools and exact output shapes

    ./cbm-tool container <path> --dump-plain body.plain
    ./cbm-tool diff <a.plain> <b.plain> [--context N]
    ./cbm-tool fuzz <container> --mutate N --rounds N --seed N [--out <dir>]

`diff` prints body sizes and context, two entropy values computed by
`cbm_decode_entropy`, then `cbm_diff_print` output: `ranges`, `changed_bytes`,
`entropy_a`, `entropy_b`, signed `entropy_delta`, and one `range`/`heatmap`
pair per changed span. Swapping arguments yields the same ranges.

`fuzz` uses a 32-bit xorshift64* stream: each round derives an independent
state from `seed` and the 1-based round number (splitmix64 finalizer); each
mutation XORs one body byte with a non-zero delta from the same stream. No
`time()`, `rand()`, locale-dependent text, or address ordering is involved.

## 4. Fuzz corpus and manifest format

Writes are restricted to `<out>/round-NNN.cbm` (`%03u` round number) and
`<out>/manifest.txt`. Each round file is exactly 85688 bytes: preserved byte 0
followed by the re-encrypted mutated body. Before writing, the encrypted body
is decrypted again and compared with the mutated plaintext; a mismatch aborts
the run.

`manifest.txt` is plain ASCII with LF line endings:

    cbm_fuzz manifest v1
    seed <unsigned long>
    mutate <unsigned>
    rounds <unsigned>
    body_len 85687
    container_sha256 <64 lowercase hex digits>
    round 001 round-001.cbm 85688 <sha256> mutations <offset>:<delta-hex>,...
    round 002 round-002.cbm 85688 <sha256> mutations ...

`mutations` is in application order; `offset` is a 0-based body offset and
`delta-hex` is the non-zero byte XORed into that offset. SHA-256 is computed
over the exact file bytes and matches `sha256sum`. The manifest lists rounds
in order, so two runs with identical `--seed`, `--mutate` and `--rounds`
produce byte-identical file names, sizes, digests and manifest text.

## 5. Safety contract

- `fuzz` refuses a block-device source and a block-device `--out` before any
  read; it never opens a device for writing.
- `--out` must be an existing directory, distinct from the source file and its
  directory; any output path resolving back to the source is refused.
- Corpus writes use `fopen`/`fwrite` to `--out` only, never the paced
  `cbm_file_write` path used for devices. The source container is never
  written.
- A mutated corpus proves cipher identity, **not** that a vendor tool would
  accept the mutated body — that field-level oracle is still missing (Gap 4).
