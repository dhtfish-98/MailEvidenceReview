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
