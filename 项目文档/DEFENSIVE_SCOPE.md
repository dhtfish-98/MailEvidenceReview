# Authorized local mail evidence

The selected scope is immutable local EML structure, byte-origin header/MIME evidence, finite transfer decoding, redacted attachment metadata/digests and declared Received/date facts. Attachment bytes are hashed in memory, never written, opened or executed. Unknown raw fragments remain located in the caller-held evidence with length/digest rather than being silently discarded or exposed as report text.

There are no SMTP, IMAP, POP, DNS, HTTP or URL-fetch capabilities, sender reputation probes, Outlook conversion, subprocess target helpers, live mailbox credentials, attachment extraction, password checks, HTML-body rendering or mail delivery. The CLI reads only one explicit bounded no-follow regular snapshot. Development installation/CI uses trusted package tools separately from target mail parsing.

This independent implementation replaces the selected mail-parser MIME/header/Received mechanisms with bounded byte parsing. The old dynamic attribute helpers, normalized header collisions, trust-hop selector and permissive mail-client recovery are not carried over. It is not an audit/rewrite of the upstream entire platform, an equivalent SpamScope API or a malware/authenticity verifier. Encoded container recovery, arbitrary charsets, RFC 2047 display words, SMTPUTF8 semantics, MIME fragments/external bodies, mail-client UI behavior, every filesystem race, deployment and independent human review remain OPEN.

CVP eligibility requires genuine lawful defensive work, applicant/organization/channel facts and any actual safeguard obstacle. Project count, source attribution, passing tests or public repositories do not establish approval. No identity, obstacle, upstream contribution or human review is fabricated.
