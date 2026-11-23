import io,csv,json,hashlib

EVIDENCE_HEADER=['记录类型','批次','来源行','业务ID','原因码','内容']

def _write_evidence(writer,closure,rid):
    for row in closure.get('signatures',[]):
        writer.writerow(['签字',rid,'',row.get('role',''),row.get('decision',''),
            json.dumps(row,ensure_ascii=False,sort_keys=True)])
    writer.writerow(['结案',rid,'','','',json.dumps({
        'version':closure.get('version'),'evidence_sha256':closure.get('evidence_sha256'),
        'coverage_digest':closure.get('coverage_digest'),'finance_digest':closure.get('finance_digest'),
        'created_at':closure.get('created_at')},ensure_ascii=False,sort_keys=True)])

def bundle(state,closure=None):
    """Single evidence CSV.  When a closure is supplied the same signature
    evidence that the workbench published is embedded verbatim and the export
    checksum covers it, so a download can never drift onto unsigned facts."""
    if closure is None:closure=state.get('closure')
    out=io.StringIO(newline='');writer=csv.writer(out)
    writer.writerow(EVIDENCE_HEADER)
    rid=state.get('run_id','preview')
    writer.writerow(['运行清单',rid,'','','',json.dumps(state.get('manifest',{}),ensure_ascii=False,sort_keys=True)])
    writer.writerow(['对账',rid,'','','',json.dumps(state.get('reconcile',{}),ensure_ascii=False,sort_keys=True)])
    for row in state.get('calculations',[]):writer.writerow(['计算',rid,row.get('line',''),row.get('id',''),row.get('code',''),json.dumps(row,ensure_ascii=False,sort_keys=True)])
    for row in state['quarantine']:writer.writerow(['隔离',rid,row['line'],row.get('id',''),row['code'],json.dumps(row.get('raw',{}),ensure_ascii=False,sort_keys=True)])
    if closure:_write_evidence(writer,closure,rid)
    return '﻿'+out.getvalue()

def checksum(state,closure=None):
    return hashlib.sha256(bundle(state,closure).encode('utf-8')).hexdigest()
