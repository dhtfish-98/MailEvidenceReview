"""Header-declared time and Received fragments; no trust or delivery inference."""
from datetime import datetime,timedelta,timezone
import re
from .contracts import Incomplete,digest

_MONTHS={m:i+1 for i,m in enumerate('jan feb mar apr may jun jul aug sep oct nov dec'.split())}
_WEEKDAYS='mon tue wed thu fri sat sun'.split()
_DATE=re.compile(rb'(?:(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s*,\s*)?([0-9]{1,2})\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+([0-9]{4})\s+([0-9]{2}):([0-9]{2})(?::([0-9]{2}))?(?:\s+([+-][0-9]{4}|[A-Za-z]+))?',re.I|re.ASCII)
_ZONES={b'ut':0,b'gmt':0,b'est':-300,b'edt':-240,b'cst':-360,b'cdt':-300,b'mst':-420,b'mdt':-360,b'pst':-480,b'pdt':-420}
_CLAUSES=frozenset((b'from',b'by',b'with',b'via',b'id',b'for',b'envelope-from'))

def lexical(data,evidence,header,part,base=0):
    """Yield original spans of top-level atoms/delimiters; comments are balanced."""
    i=0;out=[];plain=bytearray();positions=[]
    while i<len(data):
        c=data[i]
        if c==40:
            start=i;depth=1;i+=1
            while i<len(data) and depth:
                c=data[i];i+=1
                if c==92:
                    if i<len(data):i+=1
                    else:break
                elif c==40:
                    depth+=1
                    if depth>evidence.limits.comment_depth:raise Incomplete('comment_budget')
                elif c==41:depth-=1
            if depth:
                evidence.emit('trace_comment_unclosed','OPEN',header.position(base+start),part)
            plain.append(32);positions.append(base+start);continue
        if c in (34,91,60):
            start=i;close={34:34,91:93,60:62}[c];i+=1;closed=False
            while i<len(data):
                ch=data[i];i+=1
                if ch==92:
                    if i<len(data):i+=1
                    else:break
                elif ch==close:closed=True;break
            if not closed:evidence.emit('trace_quoted_or_literal_unclosed','OPEN',header.position(base+start),part)
            out.append((data[start:i],base+start,base+i,False))
            plain.extend(data[start:i]);positions.extend(range(base+start,base+i));continue
        if c in b' \t':
            plain.append(c);positions.append(base+i);i+=1;continue
        if c==59:
            out.append((b';',base+i,base+i+1,True));plain.append(c);positions.append(base+i);i+=1;continue
        start=i
        while i<len(data) and data[i] not in b' \t(;\"[<':i+=1
        out.append((data[start:i],base+start,base+i,True));plain.extend(data[start:i]);positions.extend(range(base+start,base+i))
    return out,bytes(plain),positions

def date_value(value,evidence,header,part,base=0):
    _,plain,_=lexical(value,evidence,header,part,base)
    row={'raw_sha256':digest(value),'location':evidence.location(header.position(base)), 'utc':None,'declared_offset_minutes':None}
    match=_DATE.fullmatch(plain.strip(b' \t'))
    if match is None:
        evidence.emit('date_unparsed','OPEN',header.position(base),part);return row,None
    weekday,day,month,year,hour,minute,second,zone=match.groups(); sec=int(second or b'0')
    try:
        if int(year)<1900 or sec>60:raise ValueError('date_range')
        dt=datetime(int(year),_MONTHS[month.decode('ascii').lower()],int(day),int(hour),int(minute),min(sec,59))
    except ValueError:
        evidence.emit('invalid_declared_date','FAIL',header.position(base),part)
        evidence.emit('date_unparsed','OPEN',header.position(base),part);return row,None
    if weekday and weekday.decode('ascii').lower()!=_WEEKDAYS[dt.weekday()]:
        evidence.emit('date_weekday_mismatch','FAIL',header.position(base),part)
    offset=None
    if zone is None or zone==b'-0000':
        evidence.emit('date_zone_unknown','OPEN',header.position(base),part)
    elif zone[:1] in (b'+',b'-'):
        zh,zm=int(zone[1:3]),int(zone[3:5])
        if zh>23 or zm>59:
            evidence.emit('invalid_date_zone','FAIL',header.position(base),part)
            evidence.emit('date_zone_unknown','OPEN',header.position(base),part)
        else:offset=(zh*60+zm)*(-1 if zone[:1]==b'-' else 1)
    elif zone.lower() in _ZONES:
        offset=_ZONES[zone.lower()]; row['zone_form']='obsolete_fixed_zone'
    else:evidence.emit('date_zone_unknown','OPEN',header.position(base),part)
    if sec==60:
        evidence.emit('leap_second_unverified','OPEN',header.position(base),part);return row,None
    if offset is None:return row,None
    try:utc=(dt-timedelta(minutes=offset)).replace(tzinfo=timezone.utc)
    except (ValueError,OverflowError):
        evidence.emit('date_utc_range','OPEN',header.position(base),part);return row,None
    row.update(utc=utc.isoformat(),declared_offset_minutes=offset)
    return row,utc

def received(header,evidence,part):
    tokens,_,_=lexical(header.value,evidence,header,part)
    semis=[t for t in tokens if t[0]==b';' and t[3]]
    row={'header_index':header.index,'occurrence':header.occurrence,'location':evidence.location(header.start,header.end),'clauses':[], 'unparsed_fragments':[], 'date':None, 'declared_delta_seconds':None,'hop_authenticity':'OPEN'}
    if len(semis)!=1:
        evidence.emit('received_date_separator_ambiguous','OPEN',header.start,part)
        stop=len(header.value);utc=None
    else:
        stop=semis[0][1];base=semis[0][2]
        row['date'],utc=date_value(header.value[base:],evidence,header,part,base)
    found=[t for t in tokens if t[1]<stop and t[3] and t[0].lower() in _CLAUSES]
    def fragment(a,b):
        return {'sha256':digest(header.value[a:b]),'bytes':b-a,'location':evidence.location(header.position(a),header.position(b))}
    if not found or any(t[1]<found[0][1] for t in tokens):
        end=found[0][1] if found else stop
        row['unparsed_fragments'].append(fragment(0,end))
        evidence.emit('received_unparsed_prefix','OPEN',header.start,part)
    seen=set()
    for index,(token,a,b,_) in enumerate(found):
        key=token.lower().decode('ascii');end=found[index+1][1] if index+1<len(found) else stop
        payload=header.value[b:end].strip(b' \t')
        item={'clause':key,**fragment(a,end),'value_sha256':digest(payload),'value_bytes':len(payload)}
        value_tokens=[t for t in tokens if b<=t[1]<end]
        # A finite projection of one top-level word/domain/literal. Comments
        # remain in the raw span; richer or malformed bodies stay unparsed.
        if len(value_tokens)==1:
            value=value_tokens[0][0]
            if key in ('from','by'):
                if re.fullmatch(rb'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?',value):
                    item['projection']={'kind':'declared_domain_token','normalized_sha256':digest(value.lower())}
                elif value.startswith(b'[') and value.endswith(b']'):
                    item['projection']={'kind':'declared_address_literal','sha256':digest(value)}
            elif key in ('with','via','id'):
                if re.fullmatch(rb'[\x21-\x7e]+',value):item['projection']={'kind':'declared_word','sha256':digest(value)}
            elif key in ('for','envelope-from') and value.startswith(b'<') and value.endswith(b'>'):
                item['projection']={'kind':'opaque_declared_mailbox','sha256':digest(value)}
        if 'projection' not in item and payload:
            row['unparsed_fragments'].append(fragment(b,end))
            evidence.emit('received_clause_body_unparsed','OPEN',header.position(b),part)
        row['clauses'].append(item)
        if key in seen:evidence.emit('received_duplicate_clause','OPEN',header.position(a),part)
        seen.add(key)
        if not payload:evidence.emit('received_empty_clause','OPEN',header.position(a),part)
    # Clause bodies retain byte evidence rather than pretending to validate host identity.
    return row,utc

def timeline(headers,evidence,part):
    dates=[];traces=[];previous=None
    for header in headers:
        if header.name in (b'date',b'resent-date'):
            row,_=date_value(header.value,evidence,header,part);row.update(header_index=header.index,field=header.name.decode('ascii'));dates.append(row)
        elif header.name==b'received':
            row,utc=received(header,evidence,part)
            if previous is not None and utc is not None:
                row['declared_delta_seconds']=int((previous-utc).total_seconds())
                if previous<utc:evidence.emit('received_declared_time_order_anomaly','INFO',header.start,part)
            traces.append(row);previous=utc
    return {'dates':dates,'received_wire_order':traces,'order':'latest_header_first_assertion_only'}
