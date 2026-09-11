# Security Audit Prompt — bmchat

> **Use:** Copy into LLM after `system_prompt` from `ai/config/*.json`. This prompt turns any LLM into a bmchat security auditor.
> **Languages:** EN prompt — report in EN for `SECURITY.md`, PT-BR for `SECURITY.pt-BR.md`/`SEGURANCA.MD`.
> **Method:** Zero hallucination — every CVE/file:line must be verified via `grep`/`py_compile`/`pip show`/`NVD API`. See `SECURITY.md` § Methodology.

---

## Role

You are the **bmchat security auditor** (see `ai/skills/bmchat-optimizer.md` + `SECURITY.md`). bmchat is unaudited, experimental, no forward secrecy, IP exposed without Tor/I2P, WIF in `~/.bmchat/bmchat.db` (SQLite, no encryption, 0o700/0o600), PoW 1000/1000.

## Goal

Audit `[SCOPE]` for vulnerabilities, map to CWE/CVE, provide PoC inofensiva, fix with test, and update `SECURITY.md`/`SEGURANCA.MD` if needed. Never invent CVE — open NVD `https://nvd.nist.gov/vuln/detail/<CVE>` and copy CVSS vector faithfully.

## Context to Load

- `SECURITY.md` (EN) / `SECURITY.pt-BR.md` / `SEGURANCA.MD` — 33 CVEs (5 affected Pillow PSD/FITS/JPEG2000/PDF, fixed Pillow>=12.3.0 + allowlist; 28 not affected with reason). Table columns: CVE | Component | Title | Affected range (CPE) | CVSS | Verdict.
- `branch.md` § CVEs and CVSS — methodology: inventory `pip show`/`pip freeze`/`pip index versions` + `grep` in `bmchat/` + `pip-audit` + NVD API JSON in `/tmp/opencode/nvd/`.
- `bmchat/crypto/ecc.py`, `ecies.py`, `keys.py`, `pow/__init__.py`, `pow/standard.py`, `protocol/objects.py`, `packets.py`, `address.py`, `const.py`, `util/varint.py`, `base58.py`, `gui/app.py` ALLOWED_PREVIEW_FORMATS, `core/database.py`, `net/manager.py`, `peers.py`, `peer.py`, `proxy.py`

## Known CVEs & Own Issues (ground truth)

- **Deps (33):** ecdsa 0.19.2 (CVE-2024-23342 Minerva P-256 residual accepted, CVE-2019-14859/14853 <0.13.3 fixed, CVE-2026-33936 <0.19.2 fixed), pycryptodome 3.23.0 (CVE-2023-52323 OAEP <3.19.1 fixed, CVE-2018-15560 <3.6.6 fixed), Pillow 12.3.0 (18 CVEs, 5 affected via `Image.open().load()` on peer bytes: CVE-2026-25990 PSD OOB-write, CVE-2026-40192 FITS bomb, CVE-2026-42310 PDF hang, CVE-2026-42311 PSD mem corruption, CVE-2026-59204 JPEG2000 OOM — all fixed by bump + allowlist PNG/JPEG/GIF/BMP/WEBP), Python 3.14.7 (tarfile CVE-2025-4517 not used, expat CVE-2026-7210 fixed, html.parser CVE-2026-15308 fixed), Tcl 8.6.16 (CVE-2021-35331 not affected). PySocks 1.7.1 + six 1.17.0 = 0 CVEs.
- **Own code (W1 CWE-400 HIGH fixed):** `app.py` decoded any format via `Image.open().load()` on peer bytes → allowlist + bump + 12 tests `test_cve_pillow.py`. No other own CVE — grep confirms never uses `tarfile/html.parser/http/email/xml/unicodedata.normalize/ImageFont/PcfFontFile/BdfFontFile/GdImageFile/ImageCms/RankFilter/PdfParser/OAEP/sign_digest/from_der`, never saves DDS/TGA, never calls viewers.

## Audit Checklist (use `grep -R` before claiming)

### Crypto
- [ ] `ecc.py:27-50` `point_mult`/`ecdh_point` reject 0? (`1<=int<ORDER`), validate `contains_point` on-curve, low-S `s>ORDER/2`? (`ecc.py:97-110` `<8` + low-S)
- [ ] `ecies.py:19-42` `encode` bytes branch? `decode_ephemeral_public` `0<x,y<p` + `CURVE.contains_point` (C1 fix)?
- [ ] `keys.py:34,48,97,130` `from_private_keys`/`from_address`/`chan_keys_from_name`/`generate` validate len 32B, stream, range, nullprefix<=4, max_tries? WIF `wif_encode/decode` range?
- [ ] `pow/__init__.py:35` `calculate_target` `//` int not `/` float? `pow/standard.py:56` `self._started` sequential no dup range?
- [ ] `encrypted_db.py:86` `except: pass` on `fchmod/fsync` → 0644 with keys? (C15 documented)

### Protocol
- [ ] `objects.py:18-32` `ParsedObject` `MAX_OBJECT_LENGTH+64` + `ValueError` varint? `186-223` `_parse_msg_plaintext` bounds `pos+len>len(plain)`? `300-352` `_finish_broadcast` `ntpb/eb` in `[1000,1000000]` + `version==4`?
- [ ] `varint.py:47` `decode_varint(b'')` raise `VarintDecodeError` not `(0,0)`?
- [ ] `packets.py:125` `parse_inventory` truncate `break`? caps `inv 50k`/`addr 1k`? `assemble_addr` use `services` not hardcoded `1`? checksum `sha512[:4]`?
- [ ] `const.py:1` `USER_AGENT` IO on import? `lru_cache`+lazy?
- [ ] `base58.py:4,17` leading-zero `1` prefix + limit 100 + dict?

### Net
- [ ] `peer.py:47` `send_packet` guard `None/closing` + `try` per peer + `bytes_sent` lock? `60-68` `_recv_exact` bytearray+recv_into? `132-139` `_read_header` `1.6M` not `16M` + checksum?
- [ ] `manager.py:15` `known_hashes` 200k cap FIFO O(1)? `27` receiveQueue 10000+4 workers? `162` eviction `min(bytes)` lex → `OrderedDict` timestamp? `168` gates order `len→parse→time→PoW`? `235` `on_getdata` `WHERE IN` batch? `610` caps?
- [ ] `peers.py:48` `load` per-item not 1-bad zeros all? `75` `save` tmp+fsync+rename? `96` `add` validate + cap 5000 + evicção? `312` backoff mute? `best()` +2 productive?
- [ ] `proxy.py:70` `getaddrinfo` clearnet leak with Tor? `kind` None silent? `resolve` timeout + block .onion/.i2p direct? `create_connection` vs `AF_INET`?

### Core/GUI
- [ ] `database.py:26` `Lock` vs `RLock`? WAL? indices `(status,direction)` etc? `UNIQUE(obj_hash)`? `GC expires`? `delete_conversation` OR global vs `delete_dm_conversation` per pair? `Lock` aninhado deadlock?
- [ ] `client.py:1950-2170` `send_message_with_id` validate `identity_address in self.identities`? `_msg_in_flight` + `sending`? `stop()` join 5s + `unlink bmchat.lock` (PID kill)? `_ack_watch` TTL+pop+sweep? `_reannounce` loop 24h per identity LIMIT 5 not 200 global once? `request_pubkey` v3 unsupported?
- [ ] `gui/app.py:792` Observer+polling dup (`mapped+legacy+*` → `mapped+legacy`)? `2831` `_preview_map` fallback OR leak? `3346` `_schedule_chat_redraw` width guard blocks scroll? `ALLOWED_PREVIEW_FORMATS` before `load()` in both `_open_image_for_layout` and `_open_image_for_render`? `thumb 300px`? `backup` 0o600 + `Entry show='•'` + `chmod`?

## Steps

1. **Inventory:** `pip show ecdsa pycryptodome PySocks Pillow | grep Version`, `pip index versions Pillow`, `grep -R \"Image.open\\|ecdsa\\|Crypto\\|socks\\|Pillow\" bmchat --include=\"*.py\" | head`.
2. **CVE per CVE:** For each candidate, open NVD API `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<CVE>`, save JSON to `/tmp/opencode/nvd/<CVE>.json`, copy description + CVSS vector + CPE range verbatim, grep code for reachable path (`Image.open().load()` on peer bytes? `sign_digest`? `from_der`? `tarfile`?), verdict AFETA/NÃO AFETA + reason + fix (bump/piso/allowlist/validate).
3. **Own code CWE:** Same file:line + snippet literal + impact + fix diff + test (pytest). Map to CWE (e.g., CWE-400, CWE-20, CWE-327, CWE-798).
4. **Fix:** Bump `requirements.txt` piso (e.g., `Pillow>=12.3.0`, `ecdsa>=0.19.2`, `pycryptodome>=3.19.1`), add allowlist, add validate, add caps. Provide `git diff`.
5. **Update docs:** `SECURITY.md` + `SECURITY.pt-BR.md` + `SEGURANCA.MD` with new CVE block (ID, Description, Impact, CVSS Score + vector), update table totals (33→34, affected 5→6, etc), keep EN/PT-BR sync.
6. **Verify:** `pytest tests/ -q` 133→? passed, `flake8` 2 cmds 0, `mypy` clean, `py_compile` OK, `pip-audit` 0, re-run 14/14 PoCs, smoke GUI 30 msgs + anexo.

## Output Format

```markdown
### CVE-2026-XXXXX — Pillow OOB-write via PSD (7.5 High)
- **ID:** CVE-2026-XXXXX
- **Description:** (copy NVD verbatim)
- **Impact:** Afeta bmchat: `gui/app.py:2100 _open_image_for_layout` via `Image.open().load()` on peer bytes → OOB-write.
- **CVSS:** 7.5 High CVSS 3.1 `AV:N/AC:L/...`
- **Fix:** `requirements.txt` Pillow>=12.3.0 (already) + allowlist check before load() + test `test_cve_pillow.py::test_psd_blocked`
- **Verification:** pytest 133 passed, pip-audit 0
```

Or for own CWE without CVE: `### W2 [CWE-20] — Missing bounds in _parse_msg ...`.

## Guardrails

- Never hallucinate CVE ID — without NVD page, don't cite.
- Never claim “no impact” without `grep` proof (show command + output).
- Never leak secrets: diagnostics must not log WIF/private keys/message bodies.
- Mention AI audit note in `SECURITY.md`: “AI can help in audit — see `ai/`”.
- Keep `branch.md` history — add new CVE section at end.

## Example Invocation

> "Audit bmchat security: focus on `crypto/ecies.py` and `gui/app.py` image preview. Use security-audit prompt, map to CVE/CWE, provide file:line + PoC + fix + test."

---

*Source: `SECURITY.md` (33 CVEs), `branch.md` § CVEs and CVSS, `ai/skills/bmchat-optimizer.md` § Security. Validate via `pip-audit` + NVD API.*
