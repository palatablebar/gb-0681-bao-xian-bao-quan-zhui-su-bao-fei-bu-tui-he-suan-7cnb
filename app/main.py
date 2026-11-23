import importlib,os
from flask import Flask,jsonify,request,redirect,Response
from app.config import MODULES
from app.errors import DomainError
from app.workflow import run,load
from app import store
from app.web import payload
from app.modules.m7_archive.export_out import bundle

def create_app():
    app=Flask(__name__);app.config['MAX_CONTENT_LENGTH']=2_000_000
    for entry in MODULES:app.register_blueprint(importlib.import_module('app.modules.'+entry[0]+'.handler').bp)
    @app.errorhandler(DomainError)
    def domain_error(error):return jsonify(code=error.code,message=error.message),error.status
    @app.errorhandler(404)
    def missing(error):return jsonify(code='NOT_FOUND',message='入口不存在'),404
    @app.get('/')
    def index():return redirect('/'+MODULES[0][0])
    @app.get('/healthz')
    def health():return jsonify(status='ok')
    @app.post('/api/runs')
    def submit():
        content,params=payload();state=run(content,params);return jsonify(store.save(state['run_id'],state))
    @app.get('/api/runs')
    def list_runs():return jsonify(store.history())
    @app.get('/api/runs/<run_id>')
    def get_run(run_id):return jsonify(store.describe(run_id))
    @app.post('/api/runs/<run_id>/sign')
    def sign(run_id):
        data=request.get_json(silent=True) or {}
        if not isinstance(data,dict):raise DomainError('PAYLOAD','请求必须是对象')
        return jsonify(store.sign(run_id,data.get('role'),data.get('decision','通过'),
            expected_facts=data.get('facts'),signer=data.get('signer',''),
            expected_version=data.get('version')))
    @app.post('/api/runs/<run_id>/review')
    def review(run_id):
        data=request.get_json(silent=True) or {}
        if not isinstance(data.get('version'),int):raise DomainError('VERSION','请提交复核版本')
        # A review that names a role is a two-person signature; the older
        # single-slot behaviour is preserved for callers that do not.
        if store.is_role_review(data.get('decision')):
            # The role occupies the decision slot; an optional opinion names
            # 通过/退回 (default 通过).
            return jsonify(store.sign(run_id,data.get('decision'),
                data.get('opinion','通过'),signer=data.get('signer',''),
                expected_version=data['version']))
        return jsonify(store.review(run_id,data['version'],data.get('decision')))
    @app.get('/api/runs/<run_id>/closure')
    def closure(run_id):
        state,sealed=store.load_closure(run_id)
        return jsonify(dict(sealed,run_id=state['run_id']))
    @app.get('/api/signatures')
    def signatures():return jsonify(store.signature_ledger(request.args.get('role')))
    @app.get('/api/signatures/<int:signature_id>')
    def signature(signature_id):return jsonify(store.original_signature(signature_id))
    @app.get('/api/archive/<run_id>/export.csv')
    def download(run_id):
        state,sealed=store.load_closure(run_id)
        return Response(bundle(state,sealed),mimetype='text/csv; charset=utf-8',
            headers={'Content-Disposition':'attachment; filename=evidence.csv',
                     'X-Evidence-SHA256':sealed['evidence_sha256']})
    with app.app_context():
        if not store.history():
            state=run(load('dirty.csv'),{});store.save(state['run_id'],state)
    return app

app=create_app()
if __name__=='__main__':app.run(host='0.0.0.0',port=8000)
