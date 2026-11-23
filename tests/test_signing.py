import sqlite3, threading
import pytest
from app import store
from app.errors import DomainError
from app.workflow import load, run
from app.signing import fact_digests, evidence_checksum


def _batch(client, source='clean.csv'):
    return client.post('/api/runs', json={'sample': source}).get_json()


def _sign(client, state, role):
    return client.post('/api/runs/' + state['run_id'] + '/sign',
        json={'role': role, 'facts': state['signing'][role]['required_digest']})


def _close(client, state):
    return _sign(client, state, '保障'), _sign(client, state, '财务')


def _with_swap(source, old, new):
    return source.decode('utf-8-sig').replace(old, new)


def test_download_needs_both_confirmations(client):
    s = _batch(client)
    assert client.get('/api/archive/' + s['run_id'] + '/export.csv').status_code == 409
    _sign(client, s, '保障')
    assert client.get('/api/archive/' + s['run_id'] + '/export.csv').status_code == 409
    _sign(client, s, '财务')
    assert client.get('/api/archive/' + s['run_id'] + '/export.csv').status_code == 200


def test_roles_sign_independent_layers(client):
    s = _batch(client)
    assert client.get('/api/runs/' + s['run_id']).get_json()['blockers'] == ['责任区间未签批', '补退金额未签批']
    first = _sign(client, s, '保障').get_json()
    assert first['closed'] is False and first['blockers'] == ['补退金额未签批']
    second = _sign(client, s, '财务').get_json()
    assert second['closed'] is True and second['closure']['version'] == 1


def test_amount_only_change_reuses_coverage_signature(client):
    s = _batch(client)
    _close(client, s)
    changed = _with_swap(load('clean.csv'),
        '00007,P003,1,issue,2026-01-01,2026-01-01,2027-01-01,3650,3650',
        '00007,P003,1,issue,2026-01-01,2026-01-01,2027-01-01,3650,3600')
    t = client.post('/api/runs', json={'csv': changed}).get_json()
    assert t['run_id'] != s['run_id']
    assert t['signing']['保障']['signed'] and t['signing']['保障']['reused']
    assert not t['signing']['财务']['signed']
    assert client.get('/api/archive/' + t['run_id'] + '/export.csv').status_code == 409
    _sign(client, t, '财务')
    assert client.get('/api/archive/' + t['run_id'] + '/export.csv').status_code == 200


def test_source_swap_at_same_amount_requires_coverage_review(client):
    s = _batch(client)
    _close(client, s)
    swapped = _with_swap(load('clean.csv'), '00005,P002,2,change', '00095,P002,2,change')
    t = client.post('/api/runs', json={'csv': swapped}).get_json()
    # every amount is identical, but the liability source row changed
    assert t['business']['total'] == s['business']['total']
    assert t['business']['difference'] == s['business']['difference']
    assert not t['signing']['保障']['signed']
    assert t['signing']['财务']['signed']
    assert client.get('/api/archive/' + t['run_id'] + '/export.csv').status_code == 409
    assert _sign(client, t, '保障').get_json()['closed'] is True
    assert client.get('/api/archive/' + t['run_id'] + '/export.csv').status_code == 200


def test_retry_same_opinion_adds_no_signature(client):
    s = _batch(client)
    _sign(client, s, '保障')
    a = _sign(client, s, '保障').get_json()
    b = _sign(client, s, '保障').get_json()
    assert a['signature']['created'] is False and a['signature']['signature_id'] == b['signature']['signature_id']
    assert len([x for x in client.get('/api/signatures').get_json() if x['role'] == '保障']) == 1


def test_late_opinion_cannot_overwrite(client):
    s = _batch(client)
    facts = s['signing']['财务']['required_digest']
    assert client.post('/api/runs/' + s['run_id'] + '/sign',
        json={'role': '财务', 'facts': facts, 'decision': '通过'}).status_code == 200
    late = client.post('/api/runs/' + s['run_id'] + '/sign',
        json={'role': '财务', 'facts': facts, 'decision': '退回'})
    assert late.status_code == 409 and late.get_json()['code'] == 'CONFLICT'
    # the original opinion remains recoverable by its signature id
    original = client.get('/api/signatures/1').get_json()
    assert original['role'] == '财务' and original['decision'] == '通过'


def test_stale_facts_rejected(client):
    s = _batch(client)
    swapped = _with_swap(load('clean.csv'), '00005,P002,2,change', '00095,P002,2,change')
    t = client.post('/api/runs', json={'csv': swapped}).get_json()
    # the coverage facts of batch t are not the coverage facts of batch s
    newer = t['signing']['保障']['required_digest']
    assert newer != s['signing']['保障']['required_digest']
    r = client.post('/api/runs/' + s['run_id'] + '/sign', json={'role': '保障', 'facts': newer})
    assert r.status_code == 409 and r.get_json()['code'] == 'STALE'


def test_failed_switch_keeps_old_version(client):
    s = _batch(client)
    _close(client, s)
    first = client.get('/api/archive/' + s['run_id'] + '/export.csv')
    assert first.status_code == 200
    # a new batch's failed (single-role) switch adds nothing to the old batch
    changed = _with_swap(load('clean.csv'),
        '00007,P003,1,issue,2026-01-01,2026-01-01,2027-01-01,3650,3650',
        '00007,P003,1,issue,2026-01-01,2026-01-01,2027-01-01,3650,3600')
    t = client.post('/api/runs', json={'csv': changed}).get_json()
    _sign(client, t, '保障')
    assert client.get('/api/runs/' + s['run_id'] + '/closure').status_code == 200
    again = client.get('/api/archive/' + s['run_id'] + '/export.csv')
    assert again.status_code == 200 and again.data == first.data


def test_signatures_are_append_only(client):
    s = _batch(client)
    _sign(client, s, '保障')
    with store.connection() as db:
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("UPDATE signatures SET decision='退回'")
    assert client.get('/api/signatures/1').get_json()['decision'] == '通过'


def test_download_uses_published_signature_evidence(client):
    s = _batch(client)
    _close(client, s)
    sealed = client.get('/api/runs/' + s['run_id'] + '/closure').get_json()
    response = client.get('/api/archive/' + s['run_id'] + '/export.csv')
    text = response.data.decode('utf-8-sig')
    assert response.headers['X-Evidence-SHA256'] == sealed['evidence_sha256']
    assert '签字' in text and '保障' in text and '财务' in text
    # the published evidence hash is derived from the same signature rows the
    # export embeds, so the download cannot drift onto unsigned facts
    assert sealed['evidence_sha256'] == evidence_checksum(sealed['signatures'])
    assert '"facts_sha256"' in text


def test_closure_persists_and_is_listed(client):
    s = _batch(client)
    _close(client, s)
    again = client.post('/api/runs', json={'sample': 'clean.csv'}).get_json()
    body = client.get('/api/runs/' + s['run_id']).get_json()
    assert body['closure']['version'] == 1 and body['closure']['published'] is True
    assert again['run_id'] == s['run_id']


def test_legacy_review_endpoint_still_guards_stale(client):
    s = _batch(client)
    r = client.post('/api/runs/' + s['run_id'] + '/review', json={'version': 1, 'decision': '通过'})
    assert r.status_code == 200 and r.get_json()['review_version'] == 2
    stale = client.post('/api/runs/' + s['run_id'] + '/review', json={'version': 1, 'decision': '退回'})
    assert stale.status_code == 409


def test_invalid_role_rejected(client):
    s = _batch(client)
    r = client.post('/api/runs/' + s['run_id'] + '/sign', json={'role': '理赔'})
    assert r.status_code == 422 and r.get_json()['code'] == 'ROLE'


def test_concurrent_roles_both_survive(client):
    s = _batch(client)
    app = client.application
    results = {}

    def submit(role):
        with app.test_client() as thread_client:
            results[role] = thread_client.post('/api/runs/' + s['run_id'] + '/sign',
                json={'role': role, 'facts': s['signing'][role]['required_digest']}).status_code

    threads = [threading.Thread(target=submit, args=(role,)) for role in ('保障', '财务')]
    for thread in threads: thread.start()
    for thread in threads: thread.join()
    assert results == {'保障': 200, '财务': 200}
    body = client.get('/api/runs/' + s['run_id']).get_json()
    assert body['signing']['保障']['signed'] and body['signing']['财务']['signed']
    assert body['closure']['version'] == 1


def test_concurrent_conflicting_opinions_keep_first(client):
    s = _batch(client)
    facts = s['signing']['财务']['required_digest']
    app = client.application
    codes = []
    lock = threading.Lock()

    def submit(decision):
        with app.test_client() as thread_client:
            code = thread_client.post('/api/runs/' + s['run_id'] + '/sign',
                json={'role': '财务', 'facts': facts, 'decision': decision}).status_code
        with lock: codes.append(code)

    threads = [threading.Thread(target=submit, args=(x,)) for x in ('通过', '退回')]
    for thread in threads: thread.start()
    for thread in threads: thread.join()
    assert sorted(codes) == [200, 409]
    rows = [x for x in client.get('/api/signatures').get_json() if x['role'] == '财务']
    assert len(rows) == 1


def test_note_only_change_needs_no_new_signature(client):
    s = _batch(client)
    _close(client, s)
    noted = load('clean.csv').decode('utf-8-sig').replace('保单原件', '保单原件整本')
    t = client.post('/api/runs', json={'csv': noted}).get_json()
    assert t['run_id'] != s['run_id']
    # neither layer's facts moved, so the joint confirmation carrries forward
    assert t['signing']['保障']['signed'] and t['signing']['财务']['signed']
    assert t['closure'] is not None and t['closure']['version'] == 1
    assert client.get('/api/archive/' + t['run_id'] + '/export.csv').status_code == 200


def test_one_role_rejects_keeps_previous_version_downloadable(client):
    s = _batch(client)
    _close(client, s)
    old = client.get('/api/archive/' + s['run_id'] + '/export.csv')
    assert old.status_code == 200
    changed = _with_swap(load('clean.csv'), '00005,P002,2,change', '00095,P002,2,change')
    t = client.post('/api/runs', json={'csv': changed}).get_json()
    r = client.post('/api/runs/' + t['run_id'] + '/sign',
        json={'role': '保障', 'facts': t['signing']['保障']['required_digest'], 'decision': '退回'})
    assert r.status_code == 200 and r.get_json()['closed'] is False
    assert client.get('/api/archive/' + t['run_id'] + '/export.csv').status_code == 409
    assert client.get('/api/archive/' + s['run_id'] + '/export.csv').data == old.data


def test_review_endpoint_accepts_role(client):
    s = _batch(client)
    first = client.post('/api/runs/' + s['run_id'] + '/review', json={'version': 1, 'decision': '保障'})
    assert first.status_code == 200 and first.get_json()['closed'] is False
    second = client.post('/api/runs/' + s['run_id'] + '/review', json={'version': 1, 'decision': '财务'})
    assert second.get_json()['closure']['version'] == 1
