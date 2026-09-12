import asyncio
import pytest
import httpx
import reputation
from models import EmailInput
from scoring import analyze
from safe_browsing_wire import SearchUrlsResponse, decode_response

@pytest.fixture(autouse=True)
def configured(monkeypatch):
    monkeypatch.setenv('SAFE_BROWSING_API_KEY','synthetic-test-key')
    reputation._cache.clear()


def fake_google(monkeypatch, data=None, error=None):
    calls=[]
    class Client:
        def __init__(self, **options):
            assert options['timeout'] == 3.0
            assert options['follow_redirects'] is False
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url, **kwargs):
            assert url == 'https://safebrowsing.googleapis.com/v5/urls:search'
            assert kwargs['headers']=={'X-Goog-Api-Key':'synthetic-test-key'}
            calls.append(kwargs['params'])
            if error: raise error
            wire = SearchUrlsResponse()
            try:
                wire.cache_duration.FromJsonString(data['cacheDuration'])
                for item in data.get('threats', []):
                    wire.threats.add(url=item['url'], threat_types=[2])
                content = wire.SerializeToString()
            except (KeyError, TypeError):
                content = b'invalid'
            return httpx.Response(200, content=content, request=httpx.Request('GET',url))
    monkeypatch.setattr(reputation.httpx,'AsyncClient',Client)
    return calls


def test_malicious_match(monkeypatch):
    fake_google(monkeypatch, {'threats':[{'url':'http://bad.example','threatTypes':['SOCIAL_ENGINEERING']}], 'cacheDuration':'300s'})
    check=asyncio.run(reputation.check_urls(['http://bad.example']))
    base=analyze(EmailInput(sender='a@example.com'))
    result=reputation.add_reputation(base, check)
    assert result.score==70 and result.verdict=='High Risk'
    assert result.signals[0].id=='safe_browsing_threat'
    assert result.category_scores['reputation']==70
    assert base.score==0


def test_no_match_preserves_score(monkeypatch):
    fake_google(monkeypatch, {'cacheDuration':'300s'})
    check=asyncio.run(reputation.check_urls(['https://example.com']))
    base=analyze(EmailInput(sender='a@example.com',subject='Urgent'))
    result=reputation.add_reputation(base,check)
    assert check['status']=='no_match'
    assert result.score==base.score and result.signals==base.signals
    assert result.confidence==base.confidence

@pytest.mark.parametrize('error,status',[
    (httpx.ConnectError('PRIVATE URL'),'unavailable'),
    (httpx.ReadTimeout('PRIVATE URL'),'timeout'),
    (httpx.HTTPStatusError('PRIVATE',request=httpx.Request('GET','https://example.com'),response=httpx.Response(503)),'unavailable'),
])
def test_unavailable_and_timeout(monkeypatch,error,status,caplog):
    fake_google(monkeypatch,error=error)
    check=asyncio.run(reputation.check_urls(['https://example.com']))
    assert check['status']==status
    base=analyze(EmailInput(sender='a@example.com',subject='Urgent'))
    assert reputation.add_reputation(base,check).score==5
    assert 'PRIVATE' not in caplog.text


def test_no_urls(monkeypatch):
    calls=fake_google(monkeypatch)
    assert asyncio.run(reputation.check_urls([]))['status']=='no_urls'
    assert not calls


def test_multiple_urls_cap_dedup_and_cache(monkeypatch):
    calls=fake_google(monkeypatch,{'cacheDuration':'300s'})
    urls=['https://example.com/'+str(i) for i in range(60)]
    result=asyncio.run(reputation.check_urls(urls+urls))
    assert result['checked_count']==50 and result['partial']
    assert calls==[[('urls',url) for url in urls[:50]]]
    asyncio.run(reputation.check_urls(urls))
    assert len(calls)==1
    assert 'example.com' not in str(reputation._cache)


def test_missing_key(monkeypatch):
    monkeypatch.delenv('SAFE_BROWSING_API_KEY')
    calls=fake_google(monkeypatch)
    assert asyncio.run(reputation.check_urls(['https://example.com']))['status']=='unavailable'
    assert not calls


def test_cache_expiry(monkeypatch):
    calls=fake_google(monkeypatch,{'cacheDuration':'0s'})
    for _ in range(2): asyncio.run(reputation.check_urls(['https://example.com']))
    assert len(calls)==2


def test_malformed_response(monkeypatch):
    fake_google(monkeypatch,{'threats':'invalid'})
    assert asyncio.run(reputation.check_urls(['https://example.com']))['status']=='unavailable'


def test_total_deadline(monkeypatch):
    class SlowClient:
        def __init__(self,**kwargs): pass
        async def __aenter__(self): return self
        async def __aexit__(self,*args): pass
        async def get(self,*args,**kwargs): await asyncio.sleep(1)
    monkeypatch.setattr(reputation.httpx,'AsyncClient',SlowClient)
    monkeypatch.setattr(reputation,'TIMEOUT_SECONDS',0.01)
    assert asyncio.run(reputation.check_urls(['https://example.com']))['status']=='timeout'


def test_match_adds_independent_confidence_and_caps_total():
    base=analyze(EmailInput(sender='a@example.com',authentication_results='mx; dmarc=fail',body='Urgent enter your password'))
    result=reputation.add_reputation(base,{'status':'match','checked_count':1,'partial':False})
    assert result.score==100 and result.confidence=='High'
    assert result.category_scores['authentication']==base.category_scores['authentication']
    assert result.category_scores['language']==base.category_scores['language']


def test_real_google_synthetic_protobuf_fixture():
    from pathlib import Path
    content=Path(__file__).with_name('fixtures').joinpath('google-test-threat.bin').read_bytes()
    result=decode_response(content)
    assert result['threats'][0]['threatTypes']==['SOCIAL_ENGINEERING']
    assert result['cacheDuration'].endswith('s')
