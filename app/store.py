import sqlite3,json,os
from contextlib import contextmanager
from pathlib import Path
from datetime import datetime,timezone
from app.config import RULE_VERSION
from app.errors import DomainError
from app.signing import (
    ROLES,COVERAGE,FINANCE,ROLE_LABELS,
    fact_digests,role_facts,evidence_checksum,normalize_role,normalize_decision,
)

SCHEMA='''
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY, body TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    decision TEXT NOT NULL DEFAULT "待复核"
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS signatures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role TEXT NOT NULL,
    facts_sha256 TEXT NOT NULL,
    decision TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    signer TEXT NOT NULL DEFAULT '',
    run_id TEXT NOT NULL,
    facts_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(role, facts_sha256, rule_version)
);
CREATE TABLE IF NOT EXISTS closures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    coverage_signature INTEGER NOT NULL,
    finance_signature INTEGER NOT NULL,
    coverage_digest TEXT NOT NULL,
    finance_digest TEXT NOT NULL,
    evidence_sha256 TEXT NOT NULL,
    closure_version INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(run_id, coverage_signature, finance_signature)
);
'''
# A signature is evidence.  Once written it must stay recoverable, so the
# ledger itself rejects in-place updates and deletes instead of trusting every
# caller to behave.  There is deliberately no path that "restores" an
# overwritten original, because no path can overwrite it in the first place.
IMMUTABLE='''
CREATE TRIGGER IF NOT EXISTS signatures_no_update BEFORE UPDATE ON signatures
BEGIN SELECT RAISE(ABORT,'signature rows are append-only'); END;
CREATE TRIGGER IF NOT EXISTS signatures_no_delete BEFORE DELETE ON signatures
BEGIN SELECT RAISE(ABORT,'signature rows are append-only'); END;
CREATE TRIGGER IF NOT EXISTS closures_no_update BEFORE UPDATE ON closures
BEGIN SELECT RAISE(ABORT,'closure rows are append-only'); END;
CREATE TRIGGER IF NOT EXISTS closures_no_delete BEFORE DELETE ON closures
BEGIN SELECT RAISE(ABORT,'closure rows are append-only'); END;
'''

def _now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')

@contextmanager
def connection():
    path=Path(os.environ.get('DB_PATH','data/records.db'));path.parent.mkdir(parents=True,exist_ok=True)
    db=sqlite3.connect(path,timeout=10);db.row_factory=sqlite3.Row
    try:
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript(SCHEMA)
        db.executescript(IMMUTABLE)
        yield db
        db.commit()
    except BaseException:
        db.rollback();raise
    finally:
        db.close()

def _state(db,run_id):
    row=db.execute('SELECT * FROM runs WHERE id=?',(run_id,)).fetchone()
    if not row:raise DomainError('NOT_FOUND','批次不存在',404)
    body=json.loads(row['body'])
    body.update(run_id=row['id'],review_version=row['version'],decision=row['decision'])
    return body

def save(run_id, body):
    with connection() as db:
        db.execute('INSERT OR IGNORE INTO runs(id,body) VALUES (?,?)',(run_id,json.dumps(body,ensure_ascii=False)))
        db.execute("INSERT INTO meta(key,value) VALUES ('latest',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(run_id,))
    return describe(run_id)

def get(run_id):
    with connection() as db:return _state(db,run_id)

def history():
    with connection() as db:rows=db.execute("""SELECT r.id,r.version,r.decision,
        (SELECT c.closure_version FROM closures c WHERE c.run_id=r.id ORDER BY c.closure_version DESC,c.id DESC LIMIT 1) AS closure_version,
        (SELECT c.evidence_sha256 FROM closures c WHERE c.run_id=r.id ORDER BY c.closure_version DESC,c.id DESC LIMIT 1) AS closure_evidence
        FROM runs r ORDER BY CASE WHEN r.id=(SELECT value FROM meta WHERE key='latest') THEN 0 ELSE 1 END,r.rowid DESC LIMIT 100""").fetchall()
    return [dict(r) for r in rows]

def review(run_id, version, decision):
    """Legacy single-slot review, kept byte-compatible with earlier clients."""
    if decision not in ('通过','退回'):raise DomainError('DECISION','复核状态无效')
    with connection() as db:
        cur=db.execute('UPDATE runs SET version=version+1,decision=? WHERE id=? AND version=?',(decision,run_id,version))
        if cur.rowcount!=1:
            if not db.execute('SELECT 1 FROM runs WHERE id=?',(run_id,)).fetchone():raise DomainError('NOT_FOUND','批次不存在',404)
            raise DomainError('STALE','复核版本已更新，请刷新',409)
    return get(run_id)

def is_role_review(decision):
    """Whether a review decision names a role, i.e. is a layered signature."""
    try:normalize_role(decision);return True
    except DomainError:return False

# ---------------------------------------------------------------------------
# Two-role signing
# ---------------------------------------------------------------------------

def _signature_row(db,role,digest):
    return db.execute(
        'SELECT * FROM signatures WHERE role=? AND facts_sha256=? AND rule_version=?',
        (role,digest,RULE_VERSION),
    ).fetchone()

def _evidence_rows(coverage,finance):
    rows=[]
    for row in (coverage,finance):
        rows.append({
            'role':row['role'],
            'label':ROLE_LABELS[row['role']],
            'signature_id':row['id'],
            'facts_sha256':row['facts_sha256'],
            'decision':row['decision'],
            'signer':row['signer'],
            'signed_at':row['created_at'],
            'signed_run':row['run_id'],
            'rule_version':row['rule_version'],
        })
    return rows

def _role_view(state,role,row,digest):
    return {
        'role':role,'label':ROLE_LABELS[role],'required_digest':digest,
        'signed':row is not None,
        'decision':row['decision'] if row else None,
        'signature_id':row['id'] if row else None,
        'signer':row['signer'] if row else None,
        'signed_at':row['created_at'] if row else None,
        'signed_run':row['run_id'] if row else None,
        'reused':bool(row is not None and row['run_id']!=state.get('run_id')),
    }

def _evaluate(db,state):
    """Which signatures currently match each layer's live facts.

    The coverage reviewer confirms the current intervals and their source; the
    finance reviewer confirms the current supplement/refund amounts.  Reusing a
    signature therefore depends on that role's own facts, never on the whole
    batch identity and never on the money total alone.
    """
    digests=fact_digests(state)
    rows={role:_signature_row(db,role,digests[role]) for role in ROLES}
    views={role:_role_view(state,role,rows[role],digests[role]) for role in ROLES}
    blocked=[]
    for role in ROLES:
        if rows[role] is None:blocked.append(ROLE_LABELS[role]+'未签批')
        elif rows[role]['decision']!='通过':blocked.append(ROLE_LABELS[role]+'已退回')
    if not state.get('reconcile',{}).get('balanced'):blocked.append('行数对账未平')
    if not state.get('archive',{}).get('ready'):blocked.append('归档校验未通过')
    closed=not blocked
    out={'run_id':state.get('run_id'),'closed':closed,'signing':views,
        'blockers':blocked,'any_signed':any(rows.values())}
    if closed:
        out['evidence']=_evidence_rows(rows[COVERAGE],rows[FINANCE])
        out['evidence_sha256']=evidence_checksum(out['evidence'])
    else:
        out['evidence']=[];out['evidence_sha256']=None
    return out

def _closure_dict(row,evidence):
    return {'closed':True,'published':True,'id':row['id'],'version':row['closure_version'],
        'evidence_sha256':row['evidence_sha256'],'created_at':row['created_at'],
        'coverage_digest':row['coverage_digest'],'finance_digest':row['finance_digest'],
        'signatures':evidence}

def _find_closure(db,run_id,coverage_digest,finance_digest):
    return db.execute('''SELECT * FROM closures WHERE run_id=? AND coverage_digest=? AND finance_digest=?
        ORDER BY closure_version DESC,id DESC LIMIT 1''',(run_id,coverage_digest,finance_digest)).fetchone()

def _previous_closures(db,run_id,current):
    if not run_id:return []
    rows=db.execute('SELECT * FROM closures WHERE run_id=? ORDER BY closure_version DESC,id DESC',(run_id,)).fetchall()
    current_id=(current or {}).get('id')
    return [{'version':row['closure_version'],'evidence_sha256':row['evidence_sha256'],
             'created_at':row['created_at'],'coverage_digest':row['coverage_digest'],
             'finance_digest':row['finance_digest']}
            for row in rows if row['id']!=current_id]

def _finish(db,state,evaluation):
    """Materialise the closure for the current facts, if the two roles agree.

    Publishing is idempotent and only ever records a version whose two
    signatures already exist for exactly these facts.  It never replaces a
    published row, so a failed switch leaves the old version byte-for-byte
    intact.
    """
    evaluation['closure']=None;evaluation['published']=False
    if evaluation['closed']:
        row=_publish_row(db,state,evaluation)
        if row is not None:
            if row['evidence_sha256']!=evaluation['evidence_sha256']:
                raise DomainError('EVIDENCE','归档签字证据与已发布结案版本不一致',409)
            evaluation['closure']=_closure_dict(row,evaluation['evidence'])
            evaluation['published']=True
    evaluation['previous']=_previous_closures(db,state['run_id'],evaluation.get('closure'))
    return evaluation

def _finish_readonly(db,state,evaluation):
    evaluation['closure']=None;evaluation['published']=False;evaluation['needs_publish']=False
    if evaluation['closed']:
        digests=fact_digests(state)
        row=_find_closure(db,state['run_id'],digests[COVERAGE],digests[FINANCE]) if state.get('run_id') else None
        if row is None:
            evaluation['needs_publish']=True
        elif row['evidence_sha256']!=evaluation['evidence_sha256']:
            raise DomainError('EVIDENCE','归档签字证据与已发布结案版本不一致',409)
        else:
            evaluation['closure']=_closure_dict(row,evaluation['evidence'])
            evaluation['published']=True
    evaluation['previous']=_previous_closures(db,state['run_id'],evaluation.get('closure'))
    return evaluation

def status_for_state(state):
    """Status for a state; carried-over signatures may publish its closure."""
    with connection() as db:
        evaluation=_finish_readonly(db,state,_evaluate(db,state))
        if not evaluation.pop('needs_publish'):
            return evaluation
        # Both roles already confirmed these facts in an earlier batch, so the
        # closure can be materialised now; take the write lock to do it once.
        db.execute('BEGIN IMMEDIATE')
        evaluation=_finish(db,state,_evaluate(db,state))
        evaluation.pop('needs_publish',None)
        return evaluation

def sign(run_id, role, decision, expected_facts=None, signer='', expected_version=None):
    """Record one role's confirmation of that role's current facts.

    * roles occupy independent rows, so concurrent submissions both survive;
    * the same role retrying the same opinion on the same facts is idempotent
      and appends no second signature;
    * the same role trying a different opinion on the same facts is refused and
      the original row is left untouched (it stays recoverable by signature id).
    """
    role=normalize_role(role);decision=normalize_decision(decision)
    with connection() as db:
        # BEGIN IMMEDIATE serialises the read-then-write below across workers so
        # a late opinion cannot slip in between another role's check and insert.
        db.execute('BEGIN IMMEDIATE')
        state=_state(db,run_id)
        if expected_version is not None:
            try:expected=int(expected_version)
            except (TypeError,ValueError):raise DomainError('VERSION','请提交复核版本')
            if expected!=state['review_version']:
                raise DomainError('STALE','复核版本已更新，请刷新',409)
        digest=fact_digests(state)[role]
        if expected_facts is not None and str(expected_facts)!=digest:
            raise DomainError('STALE','当前事实已更新，请刷新后按新事实签批',409)
        facts=role_facts(state)[role]
        before=_signature_row(db,role,digest)
        if before is not None and before['decision']!=decision:
            raise DomainError('CONFLICT','该角色已就当前事实签批，后到意见不得覆盖',409)
        cur=db.execute('''INSERT OR IGNORE INTO signatures
            (role,facts_sha256,decision,rule_version,signer,run_id,facts_json,created_at)
            VALUES (?,?,?,?,?,?,?,?)''',
            (role,digest,decision,RULE_VERSION,signer or '',run_id,
             json.dumps(facts,ensure_ascii=False,sort_keys=True),_now()))
        created=cur.rowcount==1
        row=_signature_row(db,role,digest)
        if row['decision']!=decision:
            # Lost a race against a conflicting opinion for the same facts.
            raise DomainError('CONFLICT','该角色已就当前事实签批，后到意见不得覆盖',409)
    evaluation=publish(run_id)
    return {'signature':{'role':role,'label':ROLE_LABELS[role],'signature_id':row['id'],
            'facts_sha256':digest,'decision':row['decision'],'signer':row['signer'],
            'signed_at':row['created_at'],'signed_run':row['run_id'],'created':created},
        'signing':evaluation['signing'],'closed':evaluation['closed'],
        'closure':evaluation.get('closure'),'blockers':evaluation['blockers'],
        'published':evaluation.get('published',False)}

def _publish_row(db,state,evaluation):
    """Append the closure for the current facts if absent; never replaces one."""
    if not evaluation['closed']:return None
    run_id=state.get('run_id')
    if not run_id:return None
    if not db.execute('SELECT 1 FROM runs WHERE id=?',(run_id,)).fetchone():return None
    digests=fact_digests(state)
    existing=_find_closure(db,state['run_id'],digests[COVERAGE],digests[FINANCE])
    if existing is not None:return existing
    version=db.execute('SELECT COALESCE(MAX(closure_version),0)+1 FROM closures WHERE run_id=?',(state['run_id'],)).fetchone()[0]
    db.execute('''INSERT OR IGNORE INTO closures
        (run_id,coverage_signature,finance_signature,coverage_digest,finance_digest,
         evidence_sha256,closure_version,created_at) VALUES (?,?,?,?,?,?,?,?)''',
        (state['run_id'],evaluation['signing'][COVERAGE]['signature_id'],
         evaluation['signing'][FINANCE]['signature_id'],
         digests[COVERAGE],digests[FINANCE],evaluation['evidence_sha256'],version,_now()))
    return _find_closure(db,state['run_id'],digests[COVERAGE],digests[FINANCE])

def publish(run_id):
    """Persist (once) the jointly confirmed closure for the current facts.

    A failed switch is a no-op: without both signatures nothing is added, so
    the previously published version stays exactly as it was.  When a new
    closure is added the old row is kept, never deleted.
    """
    with connection() as db:
        db.execute('BEGIN IMMEDIATE')
        state=_state(db,run_id)
        return _finish(db,state,_evaluate(db,state))

def load_closure(run_id):
    """The singly published, jointly confirmed version — or the reason there is none."""
    state=get(run_id)
    with connection() as db:
        evaluation=_evaluate(db,state)
        if not state.get('reconcile',{}).get('balanced'):
            raise DomainError('UNBALANCED','对账未平')
        if not evaluation['closed']:
            raise DomainError('UNPUBLISHED','结案版本尚未经保障与财务共同签批',409)
        digests=fact_digests(state)
        row=_find_closure(db,run_id,digests[COVERAGE],digests[FINANCE])
        if row is None:
            # Both layers are already confirmed for these facts (their
            # signatures carried over), so publishing is the same joint
            # confirmation, not a new one.
            db.execute('BEGIN IMMEDIATE')
            state=_state(db,run_id)
            evaluation=_evaluate(db,state)
            if not evaluation['closed']:
                raise DomainError('UNPUBLISHED','结案版本尚未经保障与财务共同签批',409)
            row=_publish_row(db,state,evaluation)
        if row is None:
            raise DomainError('UNPUBLISHED','结案版本尚未发布',409)
        if row['evidence_sha256']!=evaluation['evidence_sha256']:
            raise DomainError('EVIDENCE','归档签字证据与已发布结案版本不一致',409)
        return state,_closure_dict(row,evaluation['evidence'])

def describe(run_id):
    state=get(run_id)
    status=status_for_state(state)
    body=dict(state)
    body.update(signing=status['signing'],closure=status['closure'],
        blockers=status['blockers'],previous_closures=status['previous'],
        any_signed=status['any_signed'])
    return body

def signature_ledger(role=None):
    with connection() as db:
        if role:
            rows=db.execute('SELECT * FROM signatures WHERE role=? ORDER BY id',(role,)).fetchall()
        else:
            rows=db.execute('SELECT * FROM signatures ORDER BY id').fetchall()
    return [dict(r) for r in rows]

def original_signature(signature_id):
    """Recover the original signature row, whatever later opinions exist."""
    with connection() as db:row=db.execute('SELECT * FROM signatures WHERE id=?',(signature_id,)).fetchone()
    if not row:raise DomainError('NOT_FOUND','签字不存在',404)
    return dict(row)
