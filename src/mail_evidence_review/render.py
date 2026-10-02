"""Static escaped evidence table; original HTML and resources never enter output."""
import html
import json

def render_html(report):
    # Every fact is a literal JSON scalar/table entry; no URL attributes or executable data.
    cells=[]
    def walk(value,path):
        if isinstance(value,dict):
            for key,item in value.items():walk(item,path+'/'+str(key))
        elif isinstance(value,list):
            for index,item in enumerate(value):walk(item,path+'/'+str(index))
        else:cells.append('<tr><td>'+html.escape(path,quote=True)+'</td><td>'+html.escape(json.dumps(value,ensure_ascii=True),quote=True)+'</td></tr>')
    walk(report,'')
    return '<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; base-uri \'none\'; form-action \'none\'"><title>Mail evidence</title></head><body><h1>Mail evidence</h1><table><thead><tr><th>Fact</th><th>Value</th></tr></thead><tbody>'+''.join(cells)+'</tbody></table></body></html>'
