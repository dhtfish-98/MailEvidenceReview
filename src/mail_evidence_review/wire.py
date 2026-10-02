"""Wire field order, folding maps and exact original source ranges."""
from dataclasses import dataclass
import re
from .contracts import Incomplete,digest

_FIELD=re.compile(rb'[\x21-\x39\x3b-\x7e]+')
_KNOWN=frozenset('from to cc bcc reply-to sender subject date resent-date received message-id mime-version content-type content-disposition content-transfer-encoding content-id content-description'.split())
@dataclass(frozen=True)
class Header:
    name:bytes
    raw_name:bytes
    value:bytes
    offsets:tuple
    start:int
    end:int
    index:int
    occurrence:int
    def position(self,index):
        return self.offsets[index] if index<len(self.offsets) else self.end
    def public(self,evidence):
        return {'index':self.index,'occurrence':self.occurrence,'name':self.name.decode('ascii') if self.name.decode('ascii') in _KNOWN else None,'name_sha256':digest(self.name),'exact_name_sha256':digest(self.raw_name),'value_sha256':digest(self.value),'raw_field_sha256':digest(evidence.data[self.start:self.end]),'location':evidence.location(self.start,self.end)}

def lines(data,start,end):
    while start<end:
        stop=data.find(b'\n',start,end)
        finish=end if stop<0 else stop+1
        content=data[start:finish]
        if content.endswith(b'\n'):
            content=content[:-1]
            if content.endswith(b'\r'):content=content[:-1]
        yield start,finish,content
        start=finish

def headers(evidence,start,end,part):
    data=evidence.data; rows=[];current=None;seen={};body=end
    def finish():
        nonlocal current
        if current is None:return
        name,raw_name,value,positions,a,b=current
        if len(value)>evidence.limits.field_bytes:raise Incomplete('field_budget')
        evidence.charge('headers')
        occurrence=seen.get(name,0);seen[name]=occurrence+1
        rows.append(Header(name,raw_name,bytes(value),tuple(positions),a,b,len(rows),occurrence))
        current=None
    for a,b,text in lines(data,start,end):
        if b-start>evidence.limits.header_bytes:raise Incomplete('header_budget')
        if not text:
            finish();body=b;break
        if any(c<32 and c!=9 or c==127 for c in text):
            evidence.emit('invalid_header_control','OPEN',a,part)
        if any(c>127 for c in text):
            evidence.emit('non_ascii_header_extension_unvalidated','OPEN',a,part)
        if text[:1] in (b' ',b'\t'):
            if current is None:
                evidence.emit('orphan_header_continuation','OPEN',a,part);continue
            # Only CR/LF are removed: following wire whitespace is retained.
            current[2].extend(text);current[3].extend(range(a,a+len(text)));current[5]=b
            if len(current[2])>evidence.limits.field_bytes:raise Incomplete('field_budget')
            continue
        finish()
        colon=text.find(b':')
        if colon<=0 or _FIELD.fullmatch(text[:colon]) is None:
            evidence.emit('missing_header_separator_or_invalid_field','OPEN',a,part);body=a;break
        raw_name=text[:colon];name=raw_name.lower();value=text[colon+1:]
        current=[name,raw_name,bytearray(value),list(range(a+colon+1,a+len(text))),a,b]
    else:
        finish();evidence.emit('missing_header_body_separator','OPEN',end,part)
    return rows,body
