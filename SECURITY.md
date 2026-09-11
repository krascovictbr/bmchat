> **Language:** [English](SECURITY.md) | [Português (BR)](SECURITY.pt-BR.md)

## 🤖 AI-Assisted Audit

> See [`ai/README.md`](ai/README.md) § Supported LLMs and [`ai/prompts/security-audit.md`](ai/prompts/security-audit.md) + [`ai/skills/bmchat-optimizer.md`](ai/skills/bmchat-optimizer.md).

AI can help audit bmchat: 9 LLM configs (`ai/config/` alias `ai/llms/` — OpenAI GPT-4o/mini, Anthropic Claude 3.5 Sonnet, Google Gemini 1.5 Pro/Flash, Meta Llama 3.1, Mistral Large 2, DeepSeek V3/R1, Cohere Command R+) each with bmchat-tuned `system_prompt` + `prompts.security` (CWE/CVE, 33 CVEs, W1). The security-audit prompt teaches any LLM to verify via `grep` + `pip-audit` + NVD API (`services.nvd.nist.gov/rest/json/cves/2.0`) + `py_compile` without hallucinating CVE IDs, and the skill lists crypto/protocol/net/gui checklists with `file:line` (e.g., `crypto/ecies.py:30` curve, `gui/app.py:2100` allowlist). AI audit is complementary — still requires `pytest tests/ -q` (554 tests) + `flake8` + `mypy` + manual `pip-audit`.

## CVE-2024-23342
- ID: CVE-2024-23342
- Description: Minerva timing attack against the P-256 curve in the ecdsa package via `SigningKey.sign_digest()`; measuring signing time leaks the internal nonce and may reveal the private key. Signature verification is not affected; no planned fix (side channels out of project scope).
- Impact: None on bmchat: the app uses exclusively secp256k1 (`bmchat/crypto/ecc.py`), never P-256 nor `sign_digest()`; the NVD lists as vulnerable only versions up to 0.18.0 (installed 0.19.2); the attack requires high-precision local timing, impractical against sporadic local signatures. Residual risk documented as accepted.
- CVSS Score: 7.4 High — CVSS 3.1 `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`

## CVE-2019-14859
- ID: CVE-2019-14859
- Description: ecdsa before 0.13.3 accepted malformed signatures without checking DER encoding, making the signature malleable and allowing transaction forgery.
- Impact: None on bmchat: fixed in 0.13.3; installed 0.19.2.
- CVSS Score: 9.1 Critical — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

## CVE-2019-14853
- ID: CVE-2019-14853
- Description: ecdsa before 0.13.3 raised unexpected exceptions (or none) when decoding malformed DER signatures, allowing denial of service.
- Impact: None on bmchat: fixed in 0.13.3; installed 0.19.2. The custom `verify_signature` still catches `Exception` from the decoder as defense in depth.
- CVSS Score: 7.5 High — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

## CVE-2026-33936
- ID: CVE-2026-33936
- Description: ecdsa before 0.19.2 accepted truncated DER in `der.remove_octet_string()`; a malicious DER private key made `SigningKey.from_der()` raise an internal exception instead of rejecting cleanly, allowing denial of service to those processing untrusted DER keys.
- Impact: None on bmchat: fixed in 0.19.2 (installed version and new floor in `requirements.txt`); the app never calls `from_der` with untrusted input.
- CVSS Score: 5.3 Medium — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`

## CVE-2023-52323
- ID: CVE-2023-52323
- Description: PyCryptodome and pycryptodomex before 3.19.1 allowed side-channel leakage in OAEP decryption, exploitable for a Manger attack.
- Impact: None on bmchat: installed 3.23.0; the app never uses OAEP (uses custom ECIES with AES-256-CBC via `Crypto.Cipher.AES`).
- CVSS Score: 5.9 Medium — CVSS 3.1 `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N`

## CVE-2018-15560
- ID: CVE-2018-15560
- Description: PyCryptodome before 3.6.6 had an integer overflow in the `data_len` variable in AESNI.c, mishandling messages smaller than 16 bytes.
- Impact: None on bmchat: installed 3.23.0, outside the affected range.
- CVSS Score: 7.5 High — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

## CVE-2025-48379
- ID: CVE-2025-48379
- Description: Pillow from 11.2.0 before 11.3.0 had a heap buffer overflow when saving a large image in compressed DDS format, without checking buffer space.
- Impact: None on bmchat: installed 11.3.0, which already contains the fix; the app never saves DDS.
- CVSS Score: 7.1 High — CVSS 3.1 `AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H`

## CVE-2026-25990
- ID: CVE-2026-25990
- Description: Pillow from 10.3.0 before 12.1.1 allowed out-of-bounds write when loading a malicious PSD image.
- Impact: Affected bmchat: PSD decoder reachable via `Image.open().load()` on attachment bytes coming from peer. Fixed with `Pillow>=12.3.0` in `requirements.txt` plus preview format allowlist (`ALLOWED_PREVIEW_FORMATS`).
- CVSS Score: 7.5 High — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

## CVE-2026-40192
- ID: CVE-2026-40192
- Description: Pillow from 10.3.0 to 12.1.1 did not limit GZIP data when decoding FITS image, allowing decompression bomb with unlimited memory consumption.
- Impact: Affected bmchat: FITS decoder reachable via `Image.open().load()` on attachment bytes coming from peer. Fixed with `Pillow>=12.3.0` plus preview format allowlist.
- CVSS Score: 7.5 High — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

## CVE-2026-42308
- ID: CVE-2026-42308
- Description: Pillow before 12.2.0 could suffer integer overflow when tracking current position when a font advances by glyph with excessive value.
- Impact: No direct impact on bmchat: font APIs (`ImageFont`) are never called; fixed anyway by bump to `Pillow>=12.3.0`.
- CVSS Score: 5.5 Medium — CVSS 3.1 `AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H`

## CVE-2026-42309
- ID: CVE-2026-42309
- Description: Pillow from 11.2.1 before 12.2.0 accepted nested lists as coordinates in APIs such as `ImagePath.Path` and `ImageDraw.polygon`, with buffer overflow.
- Impact: No direct impact on bmchat: those APIs are never called; fixed anyway by bump to `Pillow>=12.3.0`.
- CVSS Score: 5.5 Medium — CVSS 3.1 `AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H`

## CVE-2026-42310
- ID: CVE-2026-42310
- Description: Pillow from 4.2.0 before 12.2.0 hung the process at 100% CPU when processing a malicious PDF.
- Impact: Affected bmchat as a precaution: the PDF plugin is registered by default in `Image.open()`, which receives peer bytes. Fixed with `Pillow>=12.3.0` plus preview format allowlist.
- CVSS Score: 5.5 Medium — CVSS 3.1 `AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H`

## CVE-2026-42311
- ID: CVE-2026-42311
- Description: Pillow from 10.3.0 before 12.2.0 could suffer memory corruption (crash or arbitrary execution) when processing a malicious PSD file.
- Impact: Affected bmchat: PSD decoder reachable via `Image.open().load()` on attachment bytes coming from peer. Fixed with `Pillow>=12.3.0` plus preview format allowlist.
- CVSS Score: 7.8 High — CVSS 3.1 `AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`

## CVE-2026-54058
- ID: CVE-2026-54058
- Description: Pillow before 12.3.0, when loading a McIdas AREA image from a file via mmap, accepted stride smaller than the actual line width, causing reads beyond the mapped region (memory leak or crash).
- Impact: No direct impact on bmchat: the app opens images via `BytesIO`, without a file name, so the mmap branch is unreachable; fixed anyway by bump to `Pillow>=12.3.0`.
- CVSS Score: 9.1 Critical — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H`

## CVE-2026-54059
- ID: CVE-2026-54059
- Description: Pillow before 12.3.0 read glyph dimensions from the METRICS section of a PCF font and allocated via `Image.frombytes()` without decompression bomb check (up to 8.5 billion pixels from 148 bytes).
- Impact: No direct impact on bmchat: `PcfFontFile` is never used; fixed anyway by bump to `Pillow>=12.3.0`.
- CVSS Score: 7.5 High — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

## CVE-2026-54060
- ID: CVE-2026-54060
- Description: Pillow before 12.3.0 built the combined bitmap in `FontFile.compile()` with `Image.new()` without decompression bomb check.
- Impact: No direct impact on bmchat: font APIs are never used; fixed anyway by bump to `Pillow>=12.3.0`.
- CVSS Score: 7.5 High — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

## CVE-2026-55379
- ID: CVE-2026-55379
- Description: Pillow before 12.3.0 read `BBX width height` from a BDF font and passed the dimensions to `Image.new()` without decompression bomb check.
- Impact: No direct impact on bmchat: `BdfFontFile` is never used; fixed anyway by bump to `Pillow>=12.3.0`.
- CVSS Score: 7.5 High — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

## CVE-2026-55380
- ID: CVE-2026-55380
- Description: Pillow before 12.3.0 read dimensions from the GD 2.x header in `GdImageFile._open()` without decompression bomb check (4.3 GB from 1037 bytes).
- Impact: No direct impact on bmchat: `GdImageFile` is never used; fixed anyway by bump to `Pillow>=12.3.0`.
- CVSS Score: 7.5 High — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

## CVE-2026-55798
- ID: CVE-2026-55798
- Description: Pillow before 12.3.0 built a `cmd.exe` command in `WindowsViewer.get_command()` with the file path without escaping and `shell=True`, allowing command injection.
- Impact: None on bmchat: external viewers are never called and the app runs on Linux.
- CVSS Score: 4.5 Medium — CVSS 3.1 `AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L`

## CVE-2026-59197
- ID: CVE-2026-59197
- Description: Pillow before 12.3.0 allowed heap out-of-bounds write via `ImageFilter.RankFilter` with very large odd filter size, due to unchecked arithmetic in `ImagingExpand()`.
- Impact: No direct impact on bmchat: `RankFilter` is never used; fixed anyway by bump to `Pillow>=12.3.0`.
- CVSS Score: 8.2 High — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H`

## CVE-2026-59198
- ID: CVE-2026-59198
- Description: Pillow from 5.2.0 to 12.3.0 read beyond the line buffer when saving an image in mode `1` with TGA RLE compression, copying heap bytes to the generated file.
- Impact: None on bmchat: the app never saves TGA; fixed anyway by bump to `Pillow>=12.3.0`.
- CVSS Score: 6.5 Medium — CVSS 3.1 `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:L`

## CVE-2026-59199
- ID: CVE-2026-59199
- Description: Pillow before 12.3.0 allowed heap out-of-bounds write via `Image.paste()`, `Image.crop()` and `Image.alpha_composite()` with coordinates near int32 limits.
- Impact: No direct impact on bmchat: the app never calls those APIs with peer coordinates (only `thumbnail`/`resize` with calculated sizes); fixed anyway by bump to `Pillow>=12.3.0`.
- CVSS Score: 7.5 High — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

## CVE-2026-59200
- ID: CVE-2026-59200
- Description: Pillow from 5.1.0 to 12.3.0 called `zlib.decompress()` in `PdfParser.PdfStream.decode()` without output ceiling (`bufsize` is only an initial hint), allowing OOM with ~950 KB of PDF.
- Impact: No direct impact on bmchat: `PdfParser` is never used; fixed anyway by bump to `Pillow>=12.3.0`.
- CVSS Score: 7.5 High — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

## CVE-2026-59204
- ID: CVE-2026-59204
- Description: Pillow from 8.2.0 to 12.2.0 accumulated `total_component_width` between tiles in JPEG2000 decoding, forcing reallocations up to image size and allowing memory exhaustion.
- Impact: Affected bmchat: JPEG2000 decoder reachable via `Image.open().load()` on attachment bytes coming from peer. Fixed with `Pillow>=12.3.0` plus preview format allowlist.
- CVSS Score: 7.5 High — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

## CVE-2026-59205
- ID: CVE-2026-59205
- Description: Pillow before 12.3.0 allowed heap corruption in `ImageCmsTransform.apply()` when the output image had a different mode than declared in the transform (LittleCMS wrote RGBA lines into a 1-byte-per-pixel line).
- Impact: No direct impact on bmchat: `ImageCms` is never used; fixed anyway by bump to `Pillow>=12.3.0`.
- CVSS Score: 7.5 High — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

## CVE-2025-4517
- ID: CVE-2025-4517
- Description: CPython's `tarfile` module allowed arbitrary write outside the extraction directory with `filter="data"` (default in 3.14+), via `extractall()`/`extract()` on untrusted tars.
- Impact: None on bmchat: `tarfile` is never used.
- CVSS Score: 9.4 Critical — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L`

## CVE-2026-7210
- ID: CVE-2026-7210
- Description: `xml.parsers.expat` and `xml.etree.ElementTree` used insufficient entropy in Expat's hash-flooding protection, allowing DoS with malicious XML (full mitigation requires libexpat 2.8.0+).
- Impact: None on bmchat: installed 3.14.7, outside affected range (3.14.0 before 3.14.6); the app never processes XML.
- CVSS Score: 7.5 High — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

## CVE-2026-15308
- ID: CVE-2026-15308
- Description: Incremental `html.parser.HTMLParser` allowed CPU DoS with repeated unterminated markup declarations in uncontrolled data.
- Impact: None on bmchat: installed 3.14.7, outside affected range (3.14.0 before 3.14.7); `html.parser` is never used.
- CVSS Score: 7.5 High — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

## CVE-2026-0865
- ID: CVE-2026-0865
- Description: User-controlled HTTP header names and values with line breaks allowed HTTP header injection.
- Impact: None on bmchat: the app does not use an HTTP client nor build headers with external input.
- CVSS Score: 5.9 Medium — CVSS 4.0 `AV:N/AC:L/AT:P/PR:H/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N`

## CVE-2026-1299
- ID: CVE-2026-1299
- Description: The `email` module's `BytesGenerator` did not quote header newlines when serializing messages, allowing header injection with badly folded `LiteralHeader`.
- Impact: None on bmchat: the `email` module is never used.
- CVSS Score: 6.0 Medium — CVSS 4.0 `AV:N/AC:L/AT:P/PR:L/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N`

## CVE-2026-3276
- ID: CVE-2026-3276
- Description: `unicodedata.normalize()` consumed excessive CPU with long alternating combining-character inputs, in all normalization forms.
- Impact: None on bmchat: `unicodedata.normalize` is never called.
- CVSS Score: 6.3 Medium — CVSS 4.0 `AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`

## CVE-2026-2297
- ID: CVE-2026-2297
- Description: The legacy `.pyc` import hook (`SourcelessFileLoader`) did not use `io.open_code()`, so `sys.audit` handlers did not fire.
- Impact: None on bmchat: the app does not use `sys.audit` hooks.
- CVSS Score: 5.7 Medium — CVSS 4.0 `AV:L/AC:L/AT:P/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N`

## CVE-2021-35331
- ID: CVE-2021-35331
- Description: Format string vulnerability in Tcl 8.6.11's `nmakehlp.c` via malicious file; significance disputed by third parties.
- Impact: None on bmchat: installed Tcl 8.6.16, outside the only affected version (8.6.11); it is a Windows build helper, not Tk runtime.
- CVSS Score: 7.8 High — CVSS 3.1 `AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`
