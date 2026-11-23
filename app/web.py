import base64
from flask import request,render_template,jsonify
from app.errors import DomainError
from app.config import TITLE,MODULES,SHORT
from app.workflow import run,load
from app.signing import ROLES,ROLE_LABELS
from app import store

def payload():
    data=request.get_json(silent=True) or {}
    if not isinstance(data,dict):raise DomainError('PAYLOAD','请求必须是对象')
    if 'csv' in data and not isinstance(data['csv'],str):raise DomainError('CSV','CSV内容必须是文本')
    sample=data.get('sample',request.args.get('sample','dirty.csv'))
    content=data.get('csv')
    return (content.encode() if isinstance(content,str) else load(sample)),data.get('parameters',{})

def api(stage):
    content,parameters=payload();state=run(content,parameters,stage)
    response=jsonify(state)
    return response

def signing_for(data,saved):
    """The signing view always reflects the facts of the state being shown."""
    if not saved:
        return {'signing':{},'closed':False,'blockers':['批次尚未保存'],'closure':None,'previous':[]}
    return store.status_for_state(saved)

def page(stage,template):
    latest=store.history();state=store.get(latest[0]['id']) if latest else run(load('dirty.csv'),{})
    source=load(request.args['sample']) if 'sample' in request.args else base64.b64decode(state['source_b64']) if state.get('source_b64') else load('dirty.csv')
    data=run(source,state.get('manifest',{}).get('parameters',{}),stage)
    try:saved=store.get(data['run_id'])
    except DomainError:saved=None
    signature=signing_for(data,saved)
    # The panel, its buttons and the download link all address the batch that is
    # actually being shown, not merely the most recently saved one.
    return render_template(template,title=TITLE,short=SHORT,modules=MODULES,current=stage,data=data,
        run=saved or state,batch=saved,history=latest,roles=ROLES,role_labels=ROLE_LABELS,
        signing=signature['signing'],closure=signature.get('closure'),blockers=signature['blockers'],
        previous_closures=signature.get('previous',[]))
