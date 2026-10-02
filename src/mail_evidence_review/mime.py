"""Byte-origin MIME tree with explicit incomplete branches and attachment evidence."""
import re
from .contracts import Incomplete,digest
from .wire import headers,lines
from .parameters import structured,unique,filename
from .encoding import decode,payload_metadata
from .timeline import timeline

_BOUNDARY=re.compile(rb"[0-9A-Za-z'()+_,./:=? -]{0,69}[0-9A-Za-z'()+_,./:=?-]")

def _one(rows,key,evidence,part):
    matches=[h for h in rows if h.name==key]
    if len(matches)>1:
        evidence.emit('duplicate_structural_mime_header','OPEN',matches[1].start,part)
    return matches[0] if matches else None

class MimeReview:
    def __init__(self,evidence,include_filenames):
        self.evidence=evidence;self.parts=[];self.include=include_filenames;self.names={}
    def span(self,start,end):
        return {'location':self.evidence.location(start,end),'bytes':end-start,'sha256':digest(self.evidence.data[start:end])}
    def part(self,start,end,parent=None,depth=0,default=b'text/plain',ancestors=(),inherited_attachment=False):
        e=self.evidence
        initial_gaps=e.incomplete_count
        if depth>e.limits.depth:raise Incomplete('depth_budget')
        e.charge('parts');e.charge('work_bytes',end-start)
        number=len(self.parts)
        row={'part':number,'parent':parent,'depth':depth,'entity':self.span(start,end),'headers':[],'children':[],'complete':False,'attachment':inherited_attachment,'filename':None}
        self.parts.append(row)
        if parent is not None:self.parts[parent]['children'].append(number)
        fields,body=headers(e,start,end,number)
        row['headers']=[h.public(e) for h in fields]
        row['timeline']=timeline(fields,e,number)
        ctype=_one(fields,b'content-type',e,number)
        params=[];valid=True
        if ctype:media,params,valid=structured(ctype,e,number,True)
        else:media=default
        # Expose only bounded syntactically valid ASCII tokens, never arbitrary field content.
        known_media=valid and re.fullmatch(rb'[a-z0-9!#$%&\'*+.^_`|~-]+/[a-z0-9!#$%&\'*+.^_`|~-]+',media) is not None
        row['media_type']=media.decode('ascii') if known_media else None
        row['media_type_sha256']=digest(media)
        row['body_wire']=self.span(body,end)
        charset=unique(params,b'charset',e,ctype,number) if ctype else None
        disposition=_one(fields,b'content-disposition',e,number)
        name=None
        if disposition:
            disp,dparams,dvalid=structured(disposition,e,number)
            row['disposition']=disp.decode('ascii') if dvalid and disp in (b'inline',b'attachment') else None
            if disp==b'attachment':row['attachment']=True
            if disp not in (b'inline',b'attachment'):e.emit('unsupported_disposition','OPEN',disposition.start,number)
            name=filename(dparams,b'filename',e,disposition,number,self.include)
        else:row['disposition']=None
        fallback=filename(params,b'name',e,ctype,number,self.include) if ctype else None
        if name and fallback:
            row['filename_alternative']=fallback
            e.emit('multiple_filename_sources','OPEN',ctype.start,number)
        name=name or fallback;row['filename']=name
        if name:
            row['attachment']=True
            collision=name.get('portable_name_sha256')
            if collision is not None:
                if collision in self.names:
                    row['filename']['potential_alias_part']=self.names[collision]
                    e.emit('portable_filename_potential_alias','INFO',body,number)
                else:self.names[collision]=number
        cte=_one(fields,b'content-transfer-encoding',e,number)
        transfer=b'7bit'
        if cte:
            transfer,extra,tvalid=structured(cte,e,number)
            if extra or not tvalid:
                e.emit('invalid_transfer_encoding_field','OPEN',cte.start,number);transfer=b'unknown'
        row['transfer_encoding']=transfer.decode('ascii') if transfer in (b'7bit',b'8bit',b'binary',b'base64',b'quoted-printable') else None
        version=_one(fields,b'mime-version',e,number)
        if version and version.value.strip(b' \t')!=b'1.0':e.emit('unsupported_mime_version','OPEN',version.start,number)
        if not known_media:
            e.emit('media_type_interpretation_incomplete','OPEN',ctype.start if ctype else start,number)
            return number
        if media.startswith(b'multipart/'):
            if transfer not in (b'7bit',b'8bit',b'binary'):
                e.emit('encoded_multipart_opaque','OPEN',body,number);return number
            boundary=unique(params,b'boundary',e,ctype,number) if ctype else None
            if boundary is None or _BOUNDARY.fullmatch(boundary) is None:
                e.emit('invalid_or_missing_boundary','OPEN',body,number);return number
            if any(boundary.startswith(old) or old.startswith(boundary) for old in ancestors):
                e.emit('nested_boundary_prefix_collision','OPEN',body,number);return number
            if transfer==b'7bit' and any(c>127 for c in e.data[body:end]):e.emit('7bit_non_ascii','FAIL',body,number)
            self.multipart(body,end,boundary,number,depth,media,ancestors+(boundary,),row['attachment'])
        elif media==b'message/rfc822':
            if transfer not in (b'7bit',b'8bit',b'binary'):
                e.emit('encoded_message_opaque','OPEN',body,number);return number
            if transfer==b'7bit' and any(c>127 for c in e.data[body:end]):
                e.emit('7bit_non_ascii','FAIL',body,number)
            if body==end:e.emit('empty_encapsulated_message','OPEN',body,number)
            else:self.part(body,end,number,depth+1,b'text/plain',ancestors,row['attachment'])
        elif media.startswith(b'message/'):
            e.emit('unsupported_message_subtype','OPEN',body,number)
        else:
            decoded=decode(e.data[body:end],transfer,e,body,number)
            text_charset=(charset or b'us-ascii') if media.startswith(b'text/') else None
            row['payload']=payload_metadata(decoded,text_charset,e,body,number)
        row['complete']=e.incomplete_count==initial_gaps
        return number
    def multipart(self,start,end,boundary,part,depth,media,ancestors,attachment):
        e=self.evidence;data=e.data;prefix=b'--'+boundary;segments=[];current=None;first=None;closed=None
        for a,b,text in lines(data,start,end):
            if not text.startswith(prefix):continue
            tail=text[len(prefix):];closing=tail.startswith(b'--')
            if closing:tail=tail[2:]
            if tail.strip(b' \t'):
                e.emit('boundary_prefix_unparsed_suffix','OPEN',a,part);continue
            if first is None:first=a
            if current is not None:
                stop=a
                if data[max(current,stop-2):stop]==b'\r\n':stop-=2
                elif data[max(current,stop-1):stop]==b'\n':stop-=1
                segments.append((current,stop))
                if len(segments)>e.limits.parts:raise Incomplete('part_budget')
            if closing:closed=b;current=None;break
            current=b
        row=self.parts[part]
        if first is None:
            e.emit('multipart_boundary_not_found','OPEN',start,part);return
        row['preamble']=self.span(start,first)
        if closed is None:
            e.emit('multipart_closing_boundary_missing','OPEN',end,part)
            if current is not None:segments.append((current,end))
        else:row['epilogue']=self.span(closed,end)
        if not segments:e.emit('multipart_without_body_part','OPEN',first,part)
        child_default=b'message/rfc822' if media==b'multipart/digest' else b'text/plain'
        for a,b in segments:self.part(a,b,part,depth+1,child_default,ancestors,attachment)
