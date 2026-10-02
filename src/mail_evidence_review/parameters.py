"""Finite MIME tokens and RFC 2231 filename continuations, without codec lookup."""
import re
import unicodedata
from .contracts import Incomplete, digest

_TOKEN = frozenset(b"!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_CONT = re.compile(rb"([a-z0-9!#$%&'+.^_`|~-]+)\*([0-9]+)(\*)?")

def text_decode(data, charset):
    name = charset.lower()
    if name in (b'utf-8', b'utf8'): return data.decode('utf-8')
    if name in (b'us-ascii', b'ascii'): return data.decode('ascii')
    if name in (b'iso-8859-1', b'latin1', b'latin-1'): return data.decode('latin-1')
    raise LookupError('unsupported_charset')

def structured(header, evidence, part, media=False):
    """Return main token and ordered parameter evidence; uncertain fields stay opaque."""
    data=header.value; i=0; n=len(data); params=[]; valid=True
    def bad(code, at):
        nonlocal valid
        valid=False; evidence.emit(code,'OPEN',header.position(at),part)
    def skip():
        nonlocal i
        while i<n:
            if data[i] in b' \t': i+=1;continue
            if data[i]!=40:return
            origin=i; depth=1;i+=1
            while i<n and depth:
                c=data[i];i+=1
                if c==92:
                    if i>=n:bad('mime_comment_escape',origin);return
                    i+=1
                elif c==40:
                    depth+=1
                    if depth>evidence.limits.comment_depth:raise Incomplete('comment_budget')
                elif c==41:depth-=1
            if depth:bad('mime_comment_unclosed',origin);return
    def token():
        nonlocal i
        a=i
        while i<n and data[i] in _TOKEN:i+=1
        return data[a:i]
    skip(); main=token().lower()
    if not main:bad('missing_mime_token',i)
    if media:
        skip()
        if i>=n or data[i]!=47:bad('invalid_media_type',i)
        else:
            i+=1;skip(); sub=token().lower();main+=b'/'+sub
            if not sub:bad('invalid_media_type',i)
    if not main:bad('missing_mime_token',0)
    skip()
    while i<n:
        if data[i]!=59:bad('mime_unparsed_fragment',i);break
        i+=1;skip();at=i;name=token().lower();skip()
        if not name or i>=n or data[i]!=61:bad('invalid_mime_parameter',at);break
        i+=1;skip();value=bytearray()
        if i<n and data[i]==34:
            i+=1;closed=False
            while i<n:
                c=data[i];i+=1
                if c==34:closed=True;break
                if c==92:
                    if i>=n:break
                    c=data[i];i+=1
                if c<32 and c!=9 or c==127:bad('mime_parameter_control',i-1)
                value.append(c)
            if not closed:bad('mime_quoted_value_unclosed',at);break
        else:
            value.extend(token())
            if not value:bad('empty_unquoted_parameter',at);break
        params.append((name,bytes(value),at))
        if len(params)>evidence.limits.parameters:raise Incomplete('parameter_budget')
        skip()
    return main, params, valid

def unique(params, name, evidence, header, part):
    rows=[(value,at) for key,value,at in params if key==name]
    if len(rows)>1:
        evidence.emit('duplicate_mime_parameter','OPEN',header.position(rows[1][1]),part)
        return None
    return rows[0][0] if rows else None

def _percent(data):
    out=bytearray();i=0
    while i<len(data):
        if data[i]==37:
            if i+2>=len(data) or any(c not in b'0123456789abcdefABCDEF' for c in data[i+1:i+3]):
                raise ValueError('invalid_percent')
            out.append(int(data[i+1:i+3],16));i+=3
        else:
            c=data[i]
            if c<=32 or c>=127 or c in b'()*\'<>@,;:\\"/[]?=':
                raise ValueError('invalid_extended_attribute_character')
            out.append(c);i+=1
    return bytes(out)

def filename(params, key, evidence, header, part, include):
    plain=[(v,a) for k,v,a in params if k==key]
    extended=[(v,a) for k,v,a in params if k==key+b'*']
    continuation=[]
    for k,v,a in params:
        match=_CONT.fullmatch(k)
        if match and match[1]==key:
            number=match[2]
            if len(number)>3 or len(number)>1 and number.startswith(b'0'):
                evidence.emit('filename_continuation_index_invalid','OPEN',header.position(a),part);return None
            continuation.append((int(number),bool(match[3]),v,a))
    if not plain and not extended and not continuation:return None
    at=(plain or extended or [(None,continuation[0][3])])[0][1]
    record={'untrusted':True,'location':evidence.location(header.position(at)),'flags':[],'text':None}
    forms=bool(plain)+bool(extended)+bool(continuation)
    if len(plain)>1 or len(extended)>1 or forms>1:
        evidence.emit('ambiguous_filename','OPEN',header.position(at),part)
        record['flags'].append('ambiguous');return record
    charset=None; raw=None
    try:
        if plain:
            raw=plain[0][0];text=raw.decode('ascii')
        else:
            if extended:
                encoded=extended[0][0]; raw=None
                pieces=[(True,encoded)]
            else:
                continuation.sort();numbers=[r[0] for r in continuation]
                if numbers!=list(range(len(numbers))):raise ValueError('continuation_gap_or_duplicate')
                pieces=[(r[1],r[2]) for r in continuation]
            out=bytearray()
            for index,(encoded,value) in enumerate(pieces):
                if index==0 and encoded:
                    fields=value.split(b"'",2)
                    if len(fields)!=3 or not fields[0]:raise ValueError('filename_charset_prefix')
                    charset=fields[0];value=fields[2]
                out.extend(_percent(value) if encoded else value)
            raw=bytes(out);text=text_decode(raw,charset or b'ascii')
    except (ValueError,UnicodeError,LookupError):
        evidence.emit('filename_decode_incomplete','OPEN',header.position(at),part)
        record['flags'].append('decode_incomplete');return record
    record.update(bytes=len(raw),sha256=digest(raw),characters=len(text))
    if include:record['text']=text
    if '/' in text or '\\' in text:record['flags'].append('path_separator')
    if '..' in text.replace('\\','/').split('/'):record['flags'].append('parent_component')
    if text.startswith(('/', '\\')) or re.match(r'^[A-Za-z]:',text):record['flags'].append('absolute_or_drive')
    if any(ord(c)<32 or ord(c)==127 for c in text):record['flags'].append('control')
    if '<' in text or '>' in text or '&' in text:record['flags'].append('html_metacharacter')
    if text.endswith((' ','.')):record['flags'].append('trailing_space_or_dot')
    # Conservative metadata comparison only: never an extraction path.
    portable=unicodedata.normalize('NFKC',text.replace('\\','/').rsplit('/',1)[-1]).casefold().rstrip(' .')
    record['portable_name_sha256']=digest(portable.encode('utf-8'))
    return record
