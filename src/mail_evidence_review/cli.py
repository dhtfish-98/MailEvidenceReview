"""One bounded local snapshot; report to stdout without writing attachments."""
import argparse
import json
import sys
from . import __version__
from .api import review
from .contracts import Limits
from .files import read_regular
from .render import render_html

class Parser(argparse.ArgumentParser):
    def error(self,message):
        self.exit(3,'mail-evidence-review: invalid_arguments\n')

def main(argv=None):
    parser=Parser(description='Review a bounded local EML snapshot without attachment extraction.')
    parser.add_argument('--version',action='version',version=__version__)
    parser.add_argument('eml');parser.add_argument('--html',action='store_true')
    parser.add_argument('--include-filenames',action='store_true',help='Include untrusted filename text in escaped evidence output.')
    args=parser.parse_args(argv)
    try:data=read_regular(args.eml,Limits().input_bytes)
    except (ValueError,OSError,TypeError):
        sys.stdout.write(json.dumps({'schema_version':1,'status':'OPEN','complete':False,'findings':[{'code':'local_snapshot_unavailable','status':'OPEN'}]})+'\n');return 3
    report=review(data,include_filenames=args.include_filenames)
    output=render_html(report) if args.html else json.dumps(report,ensure_ascii=True,separators=(',',':'))
    try:sys.stdout.write(output+'\n')
    except (BrokenPipeError,UnicodeError):return 3
    return {'PASS':0,'FAIL':1,'OPEN':2}[report['status']]
