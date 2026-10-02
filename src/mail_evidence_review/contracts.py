"""Finite byte evidence; private content stays in the caller's source snapshot."""
from bisect import bisect_right
from dataclasses import dataclass,fields,asdict
from hashlib import sha256
import json

class Incomplete(ValueError):
    pass

@dataclass(frozen=True)
class Limits:
    input_bytes:int=4*1024*1024
    lines:int=65536
    header_bytes:int=65536
    field_bytes:int=8192
    headers:int=4096
    parts:int=512
    depth:int=16
    parameters:int=64
    comment_depth:int=16
    decoded_bytes:int=8*1024*1024
    leaf_bytes:int=2*1024*1024
    work_bytes:int=32*1024*1024
    findings:int=512
    report_bytes:int=512*1024
    def validate(self):
        maximum=Limits()
        for f in fields(self):
            value=getattr(self,f.name)
            if type(value) is not int or not 1<=value<=getattr(maximum,f.name):
                raise ValueError('invalid_limits')
        if self.report_bytes<4096: raise ValueError('invalid_limits')

def digest(data):
    return sha256(data).hexdigest()

class Evidence:
    def __init__(self,data,limits):
        self.data,self.limits=data,limits
        self.counts=dict(headers=0,parts=0,decoded_bytes=0,work_bytes=0)
        self.findings=[];self.open=False;self.fail=False;self.violation_count=0;self.incomplete_count=0
        self.starts=[0]
        self.initial_issue='input_budget' if len(data)>limits.input_bytes else None
        if self.initial_issue:return
        pos=0
        while True:
            pos=data.find(b'\n',pos)
            if pos<0:break
            pos+=1;self.starts.append(pos)
            if len(self.starts)>limits.lines:
                self.initial_issue='line_budget';break
    def location(self,offset,end=None):
        index=bisect_right(self.starts,offset)-1
        result={'byte_offset':offset,'line':index+1,'byte_column':offset-self.starts[index]}
        if end is not None:result['byte_end']=end
        return result
    def charge(self,kind,number=1):
        self.counts[kind]+=number
        if self.counts[kind]>getattr(self.limits,kind):raise Incomplete('budget_'+kind)
    def emit(self,code,status='OPEN',offset=None,part=None):
        self.open|=status=='OPEN';self.fail|=status=='FAIL';self.violation_count+=status=='FAIL'
        self.incomplete_count+=status=='OPEN'
        if len(self.findings)>=self.limits.findings:self.open=True;raise Incomplete('finding_budget')
        row={'code':code,'status':status}
        if offset is not None:row['location']=self.location(offset)
        if part is not None:row['part']=part
        self.findings.append(row)
    def finish(self,parts):
        result={'schema_version':1,'rule_version':'mail-evidence-review-1','status':'FAIL' if self.fail else 'OPEN' if self.open else 'PASS','complete':not self.open,'input_bytes':len(self.data),'input_sha256':digest(self.data) if len(self.data)<=self.limits.input_bytes else None,'counts':self.counts,'limits':asdict(self.limits),'known_defect_count':self.violation_count,'parts':parts,'findings':self.findings,'external':{'sender_identity':'OPEN','received_hop_authenticity':'OPEN','delivery':'OPEN','attachment_safety':'OPEN','body_semantics':'OPEN','cvp_eligibility':'OPEN'}}
        if len(json.dumps(result,ensure_ascii=True,separators=(',',':')).encode())>self.limits.report_bytes:
            result.update(status='FAIL' if self.fail else 'OPEN',complete=False,parts=[],findings=[{'code':'report_budget','status':'OPEN'}])
        return result
