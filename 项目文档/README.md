> 目录已整理：文档在「项目文档」，构建、缓存与暂存输入在「Build」。从仓库根目录运行 `python3 构建.py --build`；如需使用本文原有源码命令，先运行 `python3 构建.py --stage --ci`，再进入 `Build/源码`。暂存会恢复原输入路径。现有版本和历史验证记录按各自提交理解。

# MailEvidenceReview

Current implementation author and maintainer: **dhtfish98**. Current package version: **0.1.3**. Upstream authors and reused components retain their original attribution.


Review one authorized local EML byte snapshot without opening attachment content in a mail client. The independent parser records exact header order and identity, MIME tree and wire spans, attachment payload digests and untrusted filename metadata, and header-declared dates/Received fragments. The Python standard library is the only runtime dependency. Python 3.11–3.14 and POSIX directory-relative no-follow file operations are the selected implementation platform.

```sh
python -m pip install .
mail-evidence-review /physical/path/message.eml
mail-evidence-review /physical/path/message.eml --html
mail-evidence-review /physical/path/message.eml --include-filenames
```

The CLI writes evidence to stdout. The HTML form is an escaped static fact table of the same report, with no original HTML body, URL attributes or active resources. Filenames are redacted by default. Explicit `--include-filenames` includes their untrusted text; traversal, separators and potential case/path aliases are annotations, never filesystem destinations. Body bytes, addresses, subject values, unknown header names and path arguments are absent from the report. Digests are evidence identifiers and can still reveal equality or permit guessing of low-entropy source data; protect reports with the original evidence.

```python
from mail_evidence_review import review, Limits
report = review(b"Subject: synthetic\r\n\r\nhello")
assert report["input_bytes"] == 27
assert report["parts"][0]["media_type"] == "text/plain"
```

Input is immutable `bytes`; `Limits` accepts lower positive integer limits only. Byte offsets/ends and zero-based byte columns refer to the original snapshot, with one-based LF physical lines. Header folding removes CR/LF and retains following whitespace plus a map to original positions. CRLF and LF local snapshots are accepted; this is not SMTP wire-conformance validation. Case-insensitive ASCII field identity does not replace underscores with hyphens. Duplicate fields remain ordered, while duplicate structural MIME fields make interpretation OPEN.

MIME parsing uses real delimiter lines and a tree with parent/child origins. One immediately preceding CRLF/LF belongs to a boundary, so payload line endings are not silently duplicated. Boundaries are case-sensitive and 1–70 supported ASCII characters; ambiguous suffixes, ancestor prefix collisions, missing closers, unsupported encoded containers or message subtypes leave evidence OPEN. `multipart/digest` defaults its immediate entities to `message/rfc822`. Encoded container recovery or mail-client heuristics are not performed.

Leaf payloads use finite strict base64 and quoted-printable decoders or identity 7bit/8bit/binary transfer. Base64 requires canonical padding and pad bits; truncated or malformed data retains its wire digest and a defect/incomplete ledger instead of guessing recovered attachment bytes. Text charset checks cover UTF-8, ASCII and ISO-8859-1 aliases only. Other charsets and non-ASCII header extensions remain OPEN. The original bytes and their SHA-256 remain authoritative.

Filenames support ordinary ASCII parameters, a finite RFC 2231 extended/contiguous continuation form, quoted pairs and bounded comments. Ambiguous sources, duplicate/gapped/leading-zero indexes, unsupported or omitted explicit charset in an encoded first segment and invalid percent/attribute encodings stay OPEN. A continuation beginning with an unencoded segment has an ASCII-only projection; any non-ASCII byte remains OPEN. Portable-name digest comparisons use NFKC/casefold and basename/trailing-dot-space rules solely to flag potential aliases; they do not model a specific filesystem or certify safe extraction.

Date/Resent-Date and Received occurrences retain their own raw digests and locations. Supported modern four-digit-year calendar dates and fixed numeric offsets yield UTC; known obsolete UT/GMT/US-zone tokens are explicitly marked. Missing/unknown zones and `-0000` never acquire an invented local/UTC offset. Leap seconds remain unverified. Received scanning handles bounded comments, quotes, literals and top-level semicolons, retaining unknown fragments as source spans and digests. Clauses expose only a finite hashed token projection, not validated host or mailbox identity. Declared adjacent known times may have signed differences; missing timestamps break the chain and never become zero-delay hops.

`PASS` means complete interpretation within this finite structural contract, `FAIL` means a known encoding/calendar defect, and `OPEN` means incomplete/unsupported interpretation. Known FAIL takes precedence while completeness remains separately false. Every report keeps sender/hop authenticity, delivery, body semantics, attachment safety and CVP eligibility OPEN; a syntactically ordinary message is not an authentic or safe message. CLI exits: 0 PASS, 1 FAIL, 2 OPEN, 3 invalid arguments/unavailable local snapshot. Help/version are informational.

Defaults cap input at 4 MiB, 65,536 physical lines, 64 KiB per entity header, 8 KiB unfolded fields, 4,096 fields, 512 parts, depth 16, 64 parameters, 16 comment nesting, 2 MiB leaf wire payload, 8 MiB total decoded bytes, 32 MiB cumulative entity work, 512 findings and 512 KiB compact JSON report. Partial/over-budget reports cannot become complete; a report-budget fallback retains input identity and known defect count. HTML expands the bounded JSON facts into escaped rows. Reader rejects every symlink component, non-regular files, observed changes and byte limits; it does not claim protection against every concurrent rename or post-return mutation. Use physical paths on macOS (`/private/tmp` rather than `/tmp` aliases).

See [source review](<SOURCE_REVIEW.json>), [defensive scope](<DEFENSIVE_SCOPE.md>) and [validation](<VALIDATION.md>). Primary selected format references are [RFC 5322](https://www.rfc-editor.org/rfc/rfc5322.html), [RFC 2045](https://www.rfc-editor.org/rfc/rfc2045.html), [RFC 2046](https://www.rfc-editor.org/rfc/rfc2046.html) and [RFC 2231](https://www.rfc-editor.org/rfc/rfc2231.html). Their complete conformance or every extension is not claimed.

Safe local file input requires positive integer `O_NOFOLLOW`, `O_NONBLOCK`, `O_DIRECTORY` flags, plus directory-relative operations only where used by this reader. Missing, None, zero or boolean flags return the existing controlled unsupported/error result before opening input. File-reader validation covers macOS/Linux; native Windows safe file reading is not established.
