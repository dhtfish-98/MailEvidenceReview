"""Finite immutable bytes in, privacy-preserving evidence out."""
from .contracts import Limits,Evidence,Incomplete
from .mime import MimeReview

def review(data,*,limits=None,include_filenames=False):
    if type(data) is not bytes:raise TypeError('bytes_required')
    if type(include_filenames) is not bool:raise TypeError('boolean_required')
    if limits is None:limits=Limits()
    if not isinstance(limits,Limits):raise TypeError('limits_required')
    limits.validate();evidence=Evidence(data,limits);parser=MimeReview(evidence,include_filenames)
    try:
        if evidence.initial_issue:raise Incomplete(evidence.initial_issue)
        parser.part(0,len(data))
    except Incomplete as exc:
        evidence.open=True
        if len(evidence.findings)<limits.findings:evidence.findings.append({'code':str(exc),'status':'OPEN'})
    return evidence.finish(parser.parts)
