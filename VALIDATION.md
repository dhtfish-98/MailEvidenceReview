# Current licensing validation — 0.1.2

This patch removes only 2 confirmed unused complete reference-license/notice copies. New implementation author remains dhtfish98. Runtime parsing and evidence interpretation are unchanged; runtime changes are package version constants and any existing version display. The new source suite ran **47 unittest methods with nonzero PASS**. Current source identities are in SOURCE_MANIFEST.json, and LICENSE_CLEANUP.json describes the exact licensing boundary. Wheel and sdist reconstruction, fresh isolated consumer tests, CLI contracts, runtime/notice byte identity and package metadata are independently bound to the new assets in the batch release records; source tests alone do not prove those outcomes. New hosted CI and publication remain separate observations.

## Historical validation evidence

All following earlier version/count/native observations are historical evidence, not validation of this new patch. Statements below about then-retained reference copies describe the earlier artifacts. Current licensing membership is LICENSE_CLEANUP.json.

# Current validation — 0.1.1

The 2026-10-03 attribution update identifies the new implementation author and maintainer as dhtfish98. The final wheel and sdist were rebuilt, and a fresh isolated consumer ran **47 existing and targeted unittest methods successfully**, imported the installed package from site-packages, exercised the declared CLI contract and matched every shipped runtime/notice byte to current source. Wheel metadata records author dhtfish98 and version 0.1.1; RECORD and source-distribution contents were checked. Current runtime identities are in SOURCE_MANIFEST.json; ATTRIBUTION_UPDATE.json records the exact selected validation scope. The matching private build/install/test logs and artifact hashes are retained in the batch validation records, outside this public project.

This update also checks every required safe-read flag for exact positive integer capability before input is opened. API/CLI tests cover missing, None, zero and boolean flags, ordinary files and symbolic links. The PDF reader additionally refuses a FIFO before open when nonblocking capability is unavailable.

The current safe-file capability gate also requires set/frozenset directory-relative support declarations containing each actually used operation before opening input. Missing, None, empty, malformed or operation-incomplete collections yield the existing controlled unsupported result. Normal set/frozenset declarations and API/CLI rejection-before-open are regression tested.

## Historical validation evidence

The following earlier records retain their original versions, counts and fixed source identities. They are historical observations, not evidence that an old artifact is the current package.

# Measured engineering validation

Source tests exercise real MIME parent/child trees and original byte positions, a valid standard-library MIME payload comparison, duplicate header identity, folded positions, CRLF ownership, nested RFC822 and digest defaults, strict base64 lengths/padding/pad bits and QP soft lines, declared charset mismatches, unknown constructs, RFC2231 continuation/ambiguity and portable filename aliases. Date fixtures cover calendar errors, offset uncertainty, duplicate Received ordering, lexical comments/quotes/literals and signed declared differences without delivery claims.

Privacy/control fixtures reject attachment writes and target execution/network helpers, confirm default redaction and escaped filename HTML, and compare table facts with JSON facts. Actual local snapshot tests cover symlink leaf/parent, FIFO, unchanged bytes and byte-budget rejection. Malformed bytes and limits retain incomplete/error evidence; a known defect survives later finding/part/report limits. Tests use only synthetic mail data and do not submit messages to a server.

Run installed package tests from a separate working directory with source import paths unset:

```sh
python -m build
python -m pip install --no-index --no-deps dist/*.whl
python -I -m unittest discover -s /physical/path/MailEvidenceReview/tests -v
```

Measured source/consumer/CLI results, artifact hashes, independently observed source identity and exact-commit remote CI are recorded outside the source tree to avoid a self-hash cycle. A configured workflow or an author's assertion cannot count as executed CI. Packages retain the complete upstream Apache license and NOTICE. The selected upstream source was not executed, and no production-mail corpus or upstream full test suite is claimed.

OPEN: independent human review; full RFC/charset/client equivalence; original sender/Received claims, delivery and content/attachment safety; real deployments; detached upstream authenticity beyond observed fixed Git/raw bytes; every filesystem race; actual safeguard restriction, applicant identity/organization/channel and CVP approval.
