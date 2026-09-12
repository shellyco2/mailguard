import pytest
from models import EmailInput
from scoring import analyze, CATEGORY_CAPS

CASES = [
    ('corporate', {'body': 'Please review the meeting notes.', 'urls': ['https://example.com/notes'], 'authentication_results': 'mx; spf=pass; dkim=pass; dmarc=pass'}, 'Low Risk'),
    ('newsletter', {'body': 'Our weekly news. Sign in to read more.', 'urls': ['https://tracking.example.com/click?token=' + 'x'*500]}, 'Low Risk'),
    ('different_reply', {'reply_to': 'support@mailer.example'}, 'Low Risk'),
    ('urgency_only', {'subject': 'Urgent', 'body': 'Please review the slides immediately.'}, 'Low Risk'),
    ('credential_phishing', {'body': 'Urgent: enter your password to verify your account.', 'urls': ['http://192.0.2.1/login']}, 'Suspicious'),
    ('financial_request', {'body': 'Immediately send money by wire transfer.', 'reply_to': 'boss@unrelated.example', 'authentication_results': 'mx; dmarc=fail'}, 'Suspicious'),
    ('malicious_link', {'urls': ['http://example.com@192.0.2.1/login']}, 'Suspicious'),
    ('multiple_strong', {'body': 'Urgent: enter your password and send money.', 'reply_to': 'x@other.example', 'urls': ['http://example.com@192.0.2.1/login'], 'authentication_results': 'mx; spf=fail; dkim=fail; dmarc=fail'}, 'High Risk'),
]

@pytest.mark.parametrize('name,fields,verdict', CASES, ids=[case[0] for case in CASES])
def test_calibration(name, fields, verdict):
    result = analyze(EmailInput(sender='Alice <alice@example.com>', **fields))
    assert result.verdict == verdict
    assert 0 <= result.score <= 100

@pytest.mark.parametrize('header,points', [
    ('mx; spf=fail',20), ('mx; dkim=fail',20), ('mx; spf=fail; dkim=fail',25),
    ('mx; spf=fail; dkim=fail; dmarc=fail',30), ('mx; spf=fail; dmarc=pass',5),
    ('mx; spf=softfail',8), ('mx; spf=temperror',0), ('',0),
    ('mx; spf=pass (reason: dkim=fail); dmarc=pass',0),
])
def test_authentication_group(header, points):
    result = analyze(EmailInput(sender='a@example.com', authentication_results=header))
    assert result.category_scores['authentication'] == points
    assert len(result.signals) <= 1

@pytest.mark.parametrize('url,rule', [
    ('http://[2001:db8::1]/', 'url_ip_host'),
    ('https://xn--pple-43d.example/', 'url_punycode'),
    ('https://example.com.attacker.test/', 'url_misleading_domain'),
    ('https://a.b.c.d.e.example.com/', 'url_unusual_host'),
    ('https://good.example@bad.example/', 'url_userinfo'),
    ('https://bad.example:invalid/', 'url_invalid'),
])
def test_url_rules(url, rule):
    result = analyze(EmailInput(sender='a@example.com', urls=[url]))
    assert rule in {s.id for s in result.signals}


def test_legitimate_login_and_brand_name_do_not_trigger():
    result = analyze(EmailInput(sender='a@example.com', urls=['https://example.com/login', 'https://login.example.com/account']))
    assert result.score == 0


def test_long_link_is_very_weak_and_repetition_has_no_effect():
    url = 'https://example.com/?q=' + 'a'*300
    single = analyze(EmailInput(sender='a@example.com', urls=[url]))
    repeated = analyze(EmailInput(sender='a@example.com', urls=[url]*100))
    assert single.score == 1
    assert single == repeated


def test_category_caps_and_confidence():
    result = analyze(EmailInput(sender='a@example.com', **CASES[-1][1]))
    assert result.confidence == 'High'
    assert result.score == 100
    assert all(value <= CATEGORY_CAPS[name] for name,value in result.category_scores.items())
    assert result.category_scores['urls'] == 45
    assert result.category_scores['language'] == 30
    for category, points in result.category_scores.items():
        assert sum(s.points for s in result.signals if s.category == category) == points


def test_confidence_requires_independent_categories():
    only_links = analyze(EmailInput(sender='a@example.com', **CASES[6][1]))
    phishing = analyze(EmailInput(sender='a@example.com', **CASES[4][1]))
    assert only_links.verdict == 'Suspicious' and only_links.confidence == 'Low'
    assert phishing.confidence == 'Medium'
    assert analyze(EmailInput(sender='a@example.com')).confidence == 'Low'


def test_language_combination_is_stronger_than_isolated_words():
    single = analyze(EmailInput(sender='a@example.com', body='Urgent'))
    combined = analyze(EmailInput(sender='a@example.com', body='Urgent: enter your password'))
    assert single.score == 5
    assert combined.score == 30
    assert analyze(EmailInput(sender='a@example.com', body='Sign in to read the newsletter.')).score == 0


def test_attachments_explicitly_out_of_scope():
    result = analyze(EmailInput(sender='a@example.com', attachments=[{'filename':'file.exe','content_type':'application/octet-stream'}]))
    assert result.score == 0
    assert any('Attachments are not inspected' in line for line in result.limitations)


def test_output_does_not_echo_message_content():
    result = analyze(EmailInput(sender='private@example.com', subject='Urgent SECRET_SUBJECT', body='enter your password SECRET_BODY'))
    assert 'SECRET' not in result.model_dump_json()
    assert 'private@example.com' not in result.model_dump_json()

@pytest.mark.parametrize('score,action', [
    (0, 'No special action needed. Stay cautious with unexpected requests.'),
    (20, 'Review the sender and links carefully before taking action.'),
    (45, 'Avoid clicking links or sharing sensitive information until the sender is verified.'),
    (70, 'Do not click links, open attachments, or provide credentials. Verify the sender through another channel.'),
])
def test_exact_recommended_actions(score, action):
    from scoring import verdict_for
    assert verdict_for(score)[1] == action


def test_requested_synthetic_email():
    result = analyze(EmailInput(
        sender='test@example.com',
        subject='URGENT: Verify your account immediately',
        body='Your account will be suspended within 24 hours. Verify your identity immediately by signing in and confirming your password. Login here: http://192.0.2.1/login',
        urls=['http://192.0.2.1/login']))
    assert result.score == 67
    assert result.verdict == 'Suspicious'
    assert result.confidence == 'Medium'
    assert {signal.id:signal.points for signal in result.signals} == {
        'url_ip_host':25, 'url_account_path':10, 'url_http':2,
        'urgency_language':5, 'credential_language':10, 'language_combination':15}
    assert len(result.limitations) == 2
