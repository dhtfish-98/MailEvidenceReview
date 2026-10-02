import base64
from dataclasses import replace
from email import policy
from email.parser import BytesParser
from hashlib import sha256
import html
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import random
import sys
import tempfile
import unittest
from unittest.mock import patch

from mail_evidence_review import Limits,review
from mail_evidence_review.cli import main
from mail_evidence_review.files import read_regular
from mail_evidence_review.render import render_html

def h(data):return sha256(data).hexdigest()
def leaf(body=b'hello',extra=b''):return extra+b'\r\n'+body
def multi(parts,kind=b'mixed',boundary=b'b',closing=True):
    result=b'Content-Type: multipart/'+kind+b'; boundary="'+boundary+b'"\r\n\r\nPRE\r\n'
    for part in parts:result+=b'--'+boundary+b'\r\n'+part+b'\r\n'
    return result+(b'--'+boundary+b'--\r\nPOST' if closing else b'')
def codes(report):return {x['code'] for x in report['findings']}

class ReviewTests(unittest.TestCase):
    def test_plain_input_and_opaque_private_content(self):
        data=b'From: PRIVATE@example.invalid\r\nSubject: PRIVATE SUBJECT\r\n\r\nPRIVATE BODY'
        r=review(data);self.assertEqual(r['status'],'PASS');self.assertEqual(r['input_sha256'],h(data));self.assertNotIn('PRIVATE',json.dumps(r))
        self.assertEqual(r['parts'][0]['payload']['decoded_sha256'],h(b'PRIVATE BODY'));self.assertEqual(data,b'From: PRIVATE@example.invalid\r\nSubject: PRIVATE SUBJECT\r\n\r\nPRIVATE BODY')
    def test_duplicate_case_and_underscore_header_identity(self):
        r=review(b'SuBjEcT: a\r\nsubject: b\r\nX-Name: c\r\nX_Name: d\r\n\r\n')
        rows=r['parts'][0]['headers'];self.assertEqual([x['occurrence'] for x in rows],[0,1,0,0]);self.assertEqual([x['index'] for x in rows],[0,1,2,3]);self.assertNotEqual(rows[2]['name_sha256'],rows[3]['name_sha256']);self.assertNotEqual(rows[0]['exact_name_sha256'],rows[1]['exact_name_sha256'])
    def test_folded_header_numeric_original_positions(self):
        data=b'X: a\r\n\tb\r\nDate: Fri, 2 Oct 2026\r\n 12:00:00 +0900\r\n\r\n'
        r=review(data);headers=r['parts'][0]['headers'];self.assertEqual(headers[0]['value_sha256'],h(b' a\tb'));self.assertEqual(headers[1]['location']['byte_offset'],data.index(b'Date:'));self.assertEqual(r['parts'][0]['timeline']['dates'][0]['utc'],'2026-10-02T03:00:00+00:00')
    def test_lf_local_snapshot_and_crlf_body_origin(self):
        for ending in (b'\n',b'\r\n'):
            data=b'X: a'+ending+ending+b'body';r=review(data);self.assertEqual(r['status'],'PASS');self.assertEqual(r['parts'][0]['body_wire']['location']['byte_offset'],len(data)-4)
    def test_orphan_controls_invalid_field_and_no_separator(self):
        for data,code in [(b' folded\r\n\r\n','orphan_header_continuation'),(b'X: a\x00\r\n\r\n','invalid_header_control'),(b'X: \xff\r\n\r\n','non_ascii_header_extension_unvalidated'),(b'No colon\r\n','missing_header_separator_or_invalid_field'),(b'X: a','missing_header_body_separator')]:
            with self.subTest(code=code):self.assertIn(code,codes(review(data)));self.assertEqual(review(data)['status'],'OPEN')
    def test_real_multipart_decoding_and_stdlib_valid_oracle(self):
        data=multi([leaf(b'text'),leaf(b'AAEC',b'Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="a.bin"\r\nContent-Transfer-Encoding: base64\r\n')])
        r=review(data);oracle=BytesParser(policy=policy.default).parsebytes(data)
        leaves=[p for p in r['parts'] if not p['children']];self.assertEqual(len(leaves),2)
        self.assertEqual([x['payload']['decoded_sha256'] for x in leaves],[h(p.get_payload(decode=True)) for p in oracle.iter_parts()]);self.assertTrue(leaves[1]['attachment']);self.assertEqual(r['parts'][0]['preamble']['sha256'],h(b'PRE\r\n'))
    def test_delimiter_owns_exactly_one_newline(self):
        for body in (b'abc',b'abc\r\n',b'',b'\r\n'):
            r=review(multi([leaf(body)]));self.assertEqual(r['parts'][1]['payload']['decoded_sha256'],h(body))
    def test_transport_padding_and_boundary_case_sensitive(self):
        data=multi([leaf(b'a')],boundary=b'Case').replace(b'--Case\r\n',b'--Case \t\r\n');self.assertEqual(review(data)['status'],'PASS')
        wrong=data.replace(b'--Case',b'--case');self.assertIn('multipart_boundary_not_found',codes(review(wrong)))
    def test_missing_bad_boundary_and_prefix_suffix(self):
        for data in (b'Content-Type: multipart/mixed\r\n\r\nx',b'Content-Type: multipart/mixed; boundary="bad "\r\n\r\nx'):
            self.assertIn('invalid_or_missing_boundary',codes(review(data)))
        r=review(multi([leaf(b'abc')],closing=False));self.assertIn('multipart_closing_boundary_missing',codes(r));self.assertEqual(r['parts'][1]['payload']['decoded_sha256'],h(b'abc\r\n'))
        r=review(multi([leaf(b'a\r\n--bmore\r\nx')]));self.assertIn('boundary_prefix_unparsed_suffix',codes(r))
    def test_nested_multipart_and_message_rfc822_origins(self):
        child=b'Content-Type: message/rfc822\r\n\r\nFrom: nested@example.invalid\r\n\r\ninside'
        data=multi([multi([child],boundary=b'inner')]);r=review(data)
        self.assertEqual([p['parent'] for p in r['parts']],[None,0,1,2]);self.assertEqual(r['parts'][3]['entity']['location']['byte_offset'],data.index(b'From: nested'));self.assertEqual(r['parts'][3]['payload']['decoded_sha256'],h(b'inside'))
    def test_digest_default_is_nested_message(self):
        data=multi([b'\r\nFrom: x@example.invalid\r\n\r\ninside'],kind=b'digest');r=review(data);self.assertEqual([p['media_type'] for p in r['parts']],['multipart/digest','message/rfc822','text/plain'])
    def test_encoded_container_unsupported_message_and_nested_boundary(self):
        fixtures=[(b'Content-Type: message/rfc822\r\nContent-Transfer-Encoding: base64\r\n\r\neA==','encoded_message_opaque'),(b'Content-Type: message/external-body\r\n\r\nhttps://example.invalid','unsupported_message_subtype'),(multi([multi([leaf(b'x')],boundary=b'b2')]),'nested_boundary_prefix_collision'),(b'Content-Type: multipart/mixed; boundary=x\r\nContent-Transfer-Encoding: base64\r\n\r\neA==','encoded_multipart_opaque')]
        for data,code in fixtures:self.assertIn(code,codes(review(data)))
    def test_base64_roundtrip_all_short_lengths(self):
        rng=random.Random(9)
        for n in range(65):
            raw=rng.randbytes(n);wire=base64.b64encode(raw);r=review(leaf(wire,b'Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n'));self.assertEqual(r['parts'][0]['payload']['decoded_sha256'],h(raw))
    def test_base64_truncation_bad_alphabet_padding_unused_bits(self):
        for wire in (b'YQ',b'YQ=',b'YQ===',b'Y!==',b'YR==',b'YQ==x'):
            r=review(leaf(wire,b'Content-Transfer-Encoding: base64\r\n'));self.assertEqual(r['status'],'FAIL');self.assertIn('transfer_decoding_incomplete',codes(r));self.assertIsNone(r['parts'][0]['payload']['decoded_sha256'])
    def test_quoted_printable_real_soft_lines_and_defects(self):
        r=review(leaf(b'a=3Db=0A=\r\nc',b'Content-Transfer-Encoding: quoted-printable\r\n'));self.assertEqual(r['parts'][0]['payload']['decoded_sha256'],h(b'a=b\nc'))
        for wire in (b'a=',b'a=G1',b'a=0',b'\xff'):
            self.assertIn('transfer_encoding_defect',codes(review(leaf(wire,b'Content-Transfer-Encoding: quoted-printable\r\n'))))
    def test_charset_mismatch_unknown_and_latin1(self):
        self.assertIn('declared_charset_mismatch',codes(review(leaf(b'\xff',b'Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n'))))
        self.assertIn('unsupported_charset',codes(review(leaf(b'a',b'Content-Type: text/plain; charset=x-private\r\n'))))
        r=review(leaf(b'\xff',b'Content-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: 8bit\r\n'));self.assertEqual(r['parts'][0]['payload']['unicode_sha256'],h('ÿ'.encode()))
    def test_7bit_and_unknown_transfer(self):
        self.assertIn('7bit_non_ascii',codes(review(leaf(b'\xff'))));self.assertIn('unsupported_transfer_encoding',codes(review(leaf(b'a',b'Content-Transfer-Encoding: x-unknown\r\n'))))
    def test_filename_traversal_flags_never_path_or_default_text(self):
        data=leaf(b'x',b'Content-Disposition: attachment; filename="../PRIVATE.txt"\r\n');r=review(data);name=r['parts'][0]['filename'];self.assertTrue(name['untrusted']);self.assertIn('parent_component',name['flags']);self.assertNotIn('PRIVATE',json.dumps(r));self.assertEqual(review(data,include_filenames=True)['parts'][0]['filename']['text'],'../PRIVATE.txt')
    def test_rfc2231_continuation_reordering_and_unicode(self):
        data=leaf(b'x',b"Content-Disposition: attachment; filename*1*=.txt; filename*0*=utf-8''%E6%B5%8B%E8%AF%95\r\n")
        self.assertEqual(review(data,include_filenames=True)['parts'][0]['filename']['text'],'测试.txt')
    def test_rfc2231_ambiguous_missing_index_and_invalid_encoding(self):
        for parameters in (b'filename=a; filename=b',b'filename=a; filename*=utf-8\'\'b',b'filename*0=a; filename*2=b',b'filename*00=a',b'filename*=utf-8\'\'%GG',b'filename*=utf-8\'\'%FF',b'filename*=x-private\'\'abc'):
            r=review(leaf(b'x',b'Content-Disposition: attachment; '+parameters+b'\r\n'));self.assertEqual(r['status'],'OPEN')
    def test_case_and_path_name_aliases_only_metadata(self):
        data=multi([leaf(b'a',b'Content-Disposition: attachment; filename="A.TXT"\r\n'),leaf(b'b',b'Content-Disposition: attachment; filename="other/a.txt. "\r\n')]);r=review(data);self.assertIn('portable_filename_potential_alias',codes(r));self.assertEqual(r['parts'][2]['filename']['potential_alias_part'],1)
    def test_duplicate_structural_headers_and_parameters_are_open(self):
        for extra in (b'Content-Type: text/plain\r\nContent-Type: application/json\r\n',b'Content-Type: text/plain; charset=ascii; charset=utf-8\r\n',b'Content-Transfer-Encoding: 8bit; extra=x\r\n',b'MIME-Version: 2.0\r\n'):
            self.assertEqual(review(leaf(b'a',extra))['status'],'OPEN')
    def test_structured_quotes_comments_and_malformed(self):
        r=review(leaf(b'a',b'Content-Type: (x(y)) text/plain; charset="us-ascii"\r\n'));self.assertEqual(r['status'],'PASS')
        for extra in (b'Content-Type: text/plain; charset="oops\r\n',b'Content-Type: (oops text/plain\r\n',b'Content-Type: not-media\r\n',b'Content-Disposition: attachment; broken\r\n'):self.assertEqual(review(leaf(b'a',extra))['status'],'OPEN')
    def test_received_duplicate_timeline_and_timezone(self):
        data=b'Received: from a by b with ESMTP; Fri, 2 Oct 2026 12:00:00 +0900\r\nReceived: from c by a; Fri, 2 Oct 2026 02:59:00 +0000\r\n\r\nx';r=review(data);rows=r['parts'][0]['timeline']['received_wire_order'];self.assertEqual(len(rows),2);self.assertEqual(rows[1]['declared_delta_seconds'],60);self.assertEqual([c['clause'] for c in rows[0]['clauses']],['from','by','with']);self.assertEqual(rows[0]['hop_authenticity'],'OPEN')
    def test_received_semicolon_inside_comments_literals_and_quotes(self):
        data=b'Received: from "a; by quoted" (note; (more)) by [literal;]; Fri, 2 Oct 2026 03:00:00 +0000\r\n\r\n';r=review(data);row=r['parts'][0]['timeline']['received_wire_order'][0];self.assertEqual(row['date']['utc'],'2026-10-02T03:00:00+00:00');self.assertEqual([c['clause'] for c in row['clauses']],['from','by'])
    def test_received_unknown_fragments_bad_separator_and_missing_zone(self):
        for value,code in [(b'junk from a by b; Fri, 2 Oct 2026 03:00:00 +0000','received_unparsed_prefix'),(b'from a by b','received_date_separator_ambiguous'),(b'from a; extra; Fri, 2 Oct 2026 03:00:00 +0000','received_date_separator_ambiguous'),(b'from a; Fri, 2 Oct 2026 03:00:00','date_zone_unknown')]:self.assertIn(code,codes(review(b'Received: '+value+b'\r\n\r\n')))
    def test_date_invalid_unknown_offset_weekday_and_leap(self):
        cases=[(b'Fri, 31 Feb 2026 03:00:00 +0000','invalid_declared_date'),(b'Fri, 2 Oct 2026 03:00:00 -0000','date_zone_unknown'),(b'Fri, 2 Oct 2026 03:00:00 +2460','invalid_date_zone'),(b'Thu, 2 Oct 2026 03:00:00 +0000','date_weekday_mismatch'),(b'Fri, 2 Oct 2026 03:00:60 +0000','leap_second_unverified'),(b'Fri, 2 Oct 2026 03:00:00 XYZ','date_zone_unknown')]
        for value,code in cases:self.assertIn(code,codes(review(b'Date: '+value+b'\r\n\r\n')))
    def test_no_missing_hop_time_zero_and_negative_is_not_cause(self):
        data=b'Received: by a; Fri, 2 Oct 2026 02:00:00 +0000\r\nReceived: by b; Fri, 2 Oct 2026 03:00:00 +0000\r\nReceived: by c\r\nReceived: by d; Fri, 2 Oct 2026 00:00:00 +0000\r\n\r\n';r=review(data);rows=r['parts'][0]['timeline']['received_wire_order'];self.assertEqual([x['declared_delta_seconds'] for x in rows],[None,-3600,None,None]);self.assertIn('received_declared_time_order_anomaly',codes(r))
    def test_json_html_fact_table_and_untrusted_filename_escaping(self):
        r=review(leaf(b'<script>BODY_SECRET</script>',b'Content-Type: text/html\r\nContent-Disposition: inline; filename="<svg onload=alert(1)>"\r\n'),include_filenames=True);markup=render_html(r)
        self.assertNotIn('<svg',markup);self.assertNotIn('BODY_SECRET',markup);self.assertIn('&lt;svg',markup);self.assertIn("default-src 'none'",html.unescape(markup))
        class Table(HTMLParser):
            def __init__(self):super().__init__();self.rows=[];self.inside=False;self.current=''
            def handle_starttag(self,tag,attrs):
                if tag=='td':self.inside=True;self.current=''
            def handle_data(self,text):
                if self.inside:self.current+=text
            def handle_endtag(self,tag):
                if tag=='td':self.rows.append(self.current);self.inside=False
        table=Table();table.feed(markup);facts=dict(zip(table.rows[::2],table.rows[1::2]));self.assertEqual(json.loads(facts['/input_sha256']),r['input_sha256']);self.assertEqual(json.loads(facts['/parts/0/filename/text']),r['parts'][0]['filename']['text'])
    def test_limits_partial_and_fail_priority(self):
        cases=[(leaf(b'a'),replace(Limits(),input_bytes=1),'input_budget'),(leaf(b'a'),replace(Limits(),lines=1),'line_budget'),(leaf(b'abc'),replace(Limits(),leaf_bytes=2),'leaf_budget'),(b'X: long\r\n\r\n',replace(Limits(),field_bytes=2),'field_budget'),(multi([leaf(b'a'),leaf(b'b')]),replace(Limits(),parts=2),'budget_parts'),(multi([leaf(b'a')]),replace(Limits(),depth=1,work_bytes=1),'budget_work_bytes')]
        for data,limits,code in cases:r=review(data,limits=limits);self.assertIn(code,codes(r));self.assertFalse(r['complete'])
        r=review(multi([leaf(b'YQ',b'Content-Transfer-Encoding: base64\r\n'),leaf(b'x')]),limits=replace(Limits(),parts=2));self.assertEqual(r['status'],'FAIL');self.assertGreater(r['known_defect_count'],0)
    def test_finding_and_report_budget_preserve_known_defect(self):
        r=review(b'Date: Fri, 31 Feb 2026 03:00:00 +0000\r\n\r\n',limits=replace(Limits(),findings=1));self.assertEqual(r['status'],'FAIL');self.assertFalse(r['complete'])
        r=review(multi([leaf(b'x') for _ in range(12)]),limits=replace(Limits(),report_bytes=4096));self.assertEqual(r['parts'],[]);self.assertIn('report_budget',codes(r));self.assertFalse(r['complete'])
    def test_malformed_deterministic_no_uncaught_crash(self):
        rng=random.Random(71)
        for _ in range(500):
            data=rng.randbytes(rng.randrange(512));r=review(data);json.dumps(r);self.assertIn(r['status'],('PASS','FAIL','OPEN'))
    def test_no_network_exec_import_or_attachment_write(self):
        data=multi([leaf(b'cposix\nsystem\n.',b'Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="../../not-written"\r\n')])
        with patch('socket.socket',side_effect=AssertionError),patch('socket.getaddrinfo',side_effect=AssertionError),patch('subprocess.Popen',side_effect=AssertionError),patch('builtins.open',side_effect=AssertionError),patch('builtins.exec',side_effect=AssertionError),patch('builtins.eval',side_effect=AssertionError):r=review(data)
        self.assertEqual(r['parts'][1]['payload']['decoded_sha256'],h(b'cposix\nsystem\n.'))
    def test_api_type_and_limit_validation(self):
        for value in ('text',bytearray(b'x'),None):
            with self.assertRaises(TypeError):review(value)
        for limits in (replace(Limits(),input_bytes=True),replace(Limits(),depth=17),replace(Limits(),report_bytes=1)):
            with self.assertRaises(ValueError):review(b'',limits=limits)
    def test_branch_completeness_and_received_unparsed_body(self):
        data=multi([leaf(b'YQ',b'Content-Transfer-Encoding: base64\r\n'),leaf(b'ok')]);r=review(data)
        self.assertFalse(r['parts'][0]['complete']);self.assertFalse(r['parts'][1]['complete']);self.assertTrue(r['parts'][2]['complete'])
        r=review(b'Received: (comment) from a by b unknown PRIVATE_FRAGMENT; Fri, 2 Oct 2026 03:00:00 +0000\r\n\r\n')
        self.assertIn('received_clause_body_unparsed',codes(r));self.assertNotIn('received_unparsed_prefix',codes(r));self.assertTrue(r['parts'][0]['timeline']['received_wire_order'][0]['unparsed_fragments']);self.assertNotIn('PRIVATE',json.dumps(r))
    def test_independent_empty_media_bare_cr_and_false_limits_controls(self):
        for data in (b'Content-Type: /plain\r\n\r\nhello',b'\r',b'Content-Type: text/\r\n\r\nhello'):
            r=review(data);self.assertEqual(r['status'],'OPEN');self.assertFalse(r['complete']);self.assertFalse(r['parts'][0]['complete'])
        for value in (False,0,{},[]):
            with self.assertRaises(TypeError):review(b'\r\n',limits=value)
    def test_extended_filename_raw_attr_controls_and_ascii_continuation(self):
        prefix=b'Content-Disposition: attachment; filename*=utf-8\'\''
        for wire in (b"abc'def",b'abc*def'):
            r=review(leaf(b'x',prefix+wire+b'\r\n'));self.assertIn('filename_decode_incomplete',codes(r))
        r=review(leaf(b'x',b'Content-Disposition: attachment; filename*="utf-8\'\'abc def"\r\n'));self.assertIn('filename_decode_incomplete',codes(r))
        for wire,text in ((b'abc%27def',"abc'def"),(b'abc%2Adef','abc*def')):
            r=review(leaf(b'x',prefix+wire+b'\r\n'),include_filenames=True);self.assertEqual(r['parts'][0]['filename']['text'],text)
        r=review(leaf(b'x',b'Content-Disposition: attachment; filename*0=foo; filename*1*=%62ar\r\n'),include_filenames=True);self.assertEqual(r['status'],'PASS');self.assertEqual(r['parts'][0]['filename']['text'],'foobar')
    def test_qp_uncertain_trailing_transport_whitespace_no_guessed_digest(self):
        r=review(leaf(b'a \r\nb',b'Content-Transfer-Encoding: quoted-printable\r\n'));self.assertEqual(r['status'],'OPEN');self.assertIsNone(r['parts'][0]['payload']['decoded_sha256']);self.assertFalse(r['parts'][0]['complete'])
    def test_nested_message_respects_outer_transfer_assertion(self):
        inner=leaf(b'\xff',b'Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: 8bit\r\n')
        for encoding,expected in ((b'7bit','FAIL'),(b'8bit','PASS'),(b'binary','PASS')):
            r=review(leaf(inner,b'Content-Type: message/rfc822\r\nContent-Transfer-Encoding: '+encoding+b'\r\n'));self.assertEqual(r['status'],expected);self.assertEqual(r['parts'][1]['payload']['decoded_sha256'],h(b'\xff'))
    def test_snapshot_symlinks_fifos_and_unchanged(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as root:
            root=Path(root);p=root/'mail.eml';p.write_bytes(leaf(b'a'));before=p.read_bytes();self.assertEqual(read_regular(p,1000),before);self.assertEqual(p.read_bytes(),before)
            link=root/'link';link.symlink_to(p)
            with self.assertRaises(OSError):read_regular(link,1000)
            directory=root/'directory';directory.mkdir();parent=root/'parent';parent.symlink_to(directory,target_is_directory=True);(directory/'a').write_bytes(b'x')
            with self.assertRaises(OSError):read_regular(parent/'a',1000)
            fifo=root/'fifo';os.mkfifo(fifo)
            with self.assertRaises(ValueError):read_regular(fifo,1000)
            with self.assertRaises(ValueError):read_regular(p,1)
    def test_cli_privacy_exit_and_html_no_disk_output(self):
        from io import StringIO
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as root:
            p=Path(root)/'PRIVATE_PATH.eml';p.write_bytes(leaf(b'YQ',b'Content-Transfer-Encoding: base64\r\n'));output=StringIO()
            with patch('sys.stdout',output):code=main([str(p)])
            self.assertEqual(code,1);self.assertEqual(json.loads(output.getvalue())['status'],'FAIL');self.assertNotIn('PRIVATE_PATH',output.getvalue())
            output=StringIO()
            with patch('sys.stdout',output):code=main([str(p),'--html'])
            self.assertEqual(code,1);self.assertTrue(output.getvalue().startswith('<!doctype html>'));self.assertEqual([x.name for x in Path(root).iterdir()],['PRIVATE_PATH.eml'])
            output=StringIO()
            with patch('sys.stdout',output):self.assertEqual(main(['https://PRIVATE.invalid/mail']),3)
            self.assertNotIn('PRIVATE',output.getvalue())
    def test_cli_argument_error_does_not_echo_input(self):
        from io import StringIO
        error=StringIO()
        with patch('sys.stderr',error),self.assertRaises(SystemExit) as exception:main(['--PRIVATE_FLAG'])
        self.assertEqual(exception.exception.code,3);self.assertNotIn('PRIVATE',error.getvalue())

if __name__=='__main__':unittest.main()
