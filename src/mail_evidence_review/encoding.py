"""Strict finite transfer decoding; report digests, never materialize files."""
import base64
import binascii
from .contracts import Incomplete,digest
from .parameters import text_decode

def decode(data,encoding,evidence,start,part):
    if len(data)>evidence.limits.leaf_bytes:raise Incomplete('leaf_budget')
    encoding=encoding.lower()
    try:
        if encoding==b'base64':
            compact=bytes(c for c in data if c not in b' \t\r\n')
            decoded=base64.b64decode(compact,validate=True)
            if base64.b64encode(decoded)!=compact:raise ValueError('noncanonical_base64')
        elif encoding==b'quoted-printable':
            out=bytearray();i=0
            while i<len(data):
                c=data[i]
                if c==61:
                    if data[i+1:i+3]==b'\r\n':i+=3;continue
                    if data[i+1:i+2]==b'\n':i+=2;continue
                    if i+2>=len(data) or any(c not in b'0123456789ABCDEFabcdef' for c in data[i+1:i+3]):
                        raise ValueError('invalid_quoted_printable')
                    out.append(int(data[i+1:i+3],16));i+=3
                else:
                    if c in (32,9) and (i+1==len(data) or data[i+1] in (10,13)):
                        evidence.emit('quoted_printable_trailing_whitespace','OPEN',start+i,part)
                        return None
                    if c<32 and c not in (9,10,13) or c>126:raise ValueError('invalid_qp_literal')
                    out.append(c);i+=1
            decoded=bytes(out)
        elif encoding in (b'7bit',b'8bit',b'binary'):
            decoded=data
            if encoding==b'7bit' and any(c>127 for c in data):
                evidence.emit('7bit_non_ascii','FAIL',start,part)
        else:
            evidence.emit('unsupported_transfer_encoding','OPEN',start,part);return None
    except (ValueError,binascii.Error):
        evidence.emit('transfer_encoding_defect','FAIL',start,part)
        evidence.emit('transfer_decoding_incomplete','OPEN',start,part);return None
    evidence.charge('decoded_bytes',len(decoded))
    return decoded

def payload_metadata(decoded,charset,evidence,start,part):
    if decoded is None:return {'decoded_bytes':None,'decoded_sha256':None}
    row={'decoded_bytes':len(decoded),'decoded_sha256':digest(decoded)}
    if charset is not None:
        try:
            text=text_decode(decoded,charset)
            row.update(text_characters=len(text),unicode_sha256=digest(text.encode('utf-8')))
        except UnicodeError:
            evidence.emit('declared_charset_mismatch','FAIL',start,part)
            evidence.emit('text_decoding_incomplete','OPEN',start,part)
        except LookupError:evidence.emit('unsupported_charset','OPEN',start,part)
    return row
