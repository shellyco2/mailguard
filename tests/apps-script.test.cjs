// Run with node --test tests/apps-script.test.cjs from the MailGuard folder.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../Code.gs'), 'utf8');

function builder() {
  const item = { children: [] };
  for (const name of ['setText', 'setTopLabel', 'setWrapText', 'setFunctionName',
    'setOnClickAction', 'setNotification', 'setNavigation', 'setHeader', 'setTitle',
    'setBottomLabel', 'setStartIcon', 'setIcon', 'setCollapsible', 'setNumUncollapsibleWidgets']) {
    item[name] = function (value) { this[name.slice(3)] = value; return this; };
  }
  item.addWidget = item.addSection = item.pushCard = function (child) { this.children.push(child); return this; };
  item.build = function () { return this; };
  return item;
}

function setup({ configured = true, status = 200, result } = {}) {
  const calls = [];
  const ctx = {
    CardService: new Proxy({}, { get: (_, key) => key === 'Icon' ? { DESCRIPTION: 'DESCRIPTION' } : builder }),
    PropertiesService: { getScriptProperties: () => ({ getProperty: key => configured ?
      ({ MAILGUARD_BACKEND_URL: 'https://demo.example', MAILGUARD_API_KEY: 'test-key' })[key] : null }) },
    GmailApp: {
      setCurrentMessageAccessToken: token => calls.push(['token', token]),
      getMessageById: id => {
        calls.push(['id', id]);
        return {
          getFrom: () => 'Alice <alice@example.com>', getSubject: () => 'Review',
          getHeader: name => name === 'Reply-To' ? 'help@example.com' : 'mx.google.com; spf=pass',
          getPlainBody: () => 'See https://example.com/notes.',
          getBody: () => '<a href="https://other.example/?a=1&amp;b=2">Details</a>',
          getAttachments: () => { throw new Error('Attachment download forbidden'); }
        };
      }
    },
    UrlFetchApp: { fetch: (url, options) => {
      calls.push(['fetch', url, options]);
      assert.equal(url, 'https://demo.example/analyze', 'Never fetch email URLs or attachments');
      return { getResponseCode: () => status, getContentText: () => JSON.stringify(result || {
        score: 5, verdict: 'Low Risk', confidence: 'Low', confidence_explanation: 'Limited independent evidence.', signals: [{ id: 'test_signal', points: 15, explanation: '<b>Header text</b>' }],
        recommended_action: 'Verify the request.', limitations: ['No attachment content scanning.']
      }) };
    } }
  };
  vm.createContext(ctx);
  vm.runInContext(source, ctx);
  return { ctx, calls };
}
const event = { gmail: { messageId: 'current-message', accessToken: 'event-token' } };

test('click extracts only current message, posts no token/attachment bytes, renders escaped result', () => {
  const { ctx, calls } = setup();
  const response = ctx.onAnalyzeEmail(event);
  assert.deepEqual(calls.slice(0, 2), [['token', 'event-token'], ['id', 'current-message']]);
  const [, url, options] = calls.at(-1);
  assert.equal(url, 'https://demo.example/analyze');
  assert.equal(options.headers['X-MailGuard-Key'], 'test-key');
  assert.equal(options.followRedirects, false);
  const data = JSON.parse(options.payload);
  assert.equal(data.sender, 'Alice <alice@example.com>');
  assert.equal(data.reply_to, 'help@example.com');
  assert.equal(data.subject, 'Review');
  assert.equal(data.authentication_results, 'mx.google.com; spf=pass');
  assert.equal(data.body, 'See https://example.com/notes.');
  assert.deepEqual(data.attachments, []);
  assert.equal(calls.filter(call => call[0] === 'fetch').length, 1);
  assert.ok(data.urls.includes('https://other.example/?a=1&b=2'));
  assert.ok(!options.payload.includes('event-token'));
  assert.ok(!options.payload.includes('current-message'));
  const card = response.Navigation.children[0];
  assert.equal(card.children[1].children[0].Text, '\u2066&lt;b&gt;Header text&lt;/b&gt;\u2069');
});

test('URL extraction handles numeric entities, deduplication, protocol-relative and unquoted hrefs', () => {
  const { ctx } = setup();
  const urls = ctx.extractUrls('www.example.com https://example.com/a.',
    '<a href="https&#58;//example.com/a">a</a><a href=//other.example/path>x</a><a href="mailto:x@y.com">mail</a>');
  assert.deepEqual(Array.from(urls), ['https://example.com/a', 'https://other.example/path', 'https://www.example.com']);
});

test('unconfigured backend and missing event do not extract or send mail', () => {
  let setupResult = setup({ configured: false });
  assert.ok(setupResult.ctx.onAnalyzeEmail(event).Notification.Text.includes('not connected'));
  assert.equal(setupResult.calls.length, 0);
  setupResult = setup();
  assert.ok(setupResult.ctx.onAnalyzeEmail().Notification.Text.includes('Reopen'));
  assert.equal(setupResult.calls.length, 0);
});

test('backend error or malformed result displays a notice, never a risk verdict', () => {
  for (const config of [{ status: 500 }, { status: 401 }, { result: { score: 999 } }]) {
    const { ctx } = setup(config);
    const response = ctx.onAnalyzeEmail(event);
    assert.ok(response.Notification);
    assert.equal(response.Navigation, undefined);
  }
});

test('oversized extraction stops instead of silently sending incomplete data', () => {
  const { ctx } = setup();
  assert.throws(() => ctx.extractUrls('https://example.com/' + 'x'.repeat(4096), ''));
  assert.throws(() => ctx.extractUrls(Array.from({ length: 201 }, (_, i) => 'https://example.com/' + i).join(' '), ''));
});

test('manifest uses narrow click-time access', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, '../appsscript.json'), 'utf8'));
  assert.ok(manifest.oauthScopes.includes('https://www.googleapis.com/auth/gmail.addons.current.message.action'));
  assert.ok(!manifest.oauthScopes.some(scope => scope.endsWith('/gmail.readonly') || scope === 'https://mail.google.com/'));
});



for (const [verdict, score, count] of [
  ['Low Risk', 0, 0], ['Moderate Risk', 30, 2],
  ['Suspicious', 67, 3], ['High Risk', 90, 3]
]) {
  test(verdict + ': compact summary, prioritized reasons, action and collapsed details', () => {
    const { ctx } = setup();
    const signals = count ? [5, 20, 10, 25].map(points => ({id:'signal'+points, points, explanation:'Reason '+points})) : [];
    const result = {score, verdict, confidence:'Medium', confidence_explanation:'Evidence across categories.',
      recommended_action:'Verify the sender.', limitations:[], signals};
    const original = JSON.stringify(result);
    const card = ctx.buildResultCard(result);
    assert.equal(JSON.stringify(result), original, 'Rendering never changes analysis data');
    assert.equal(card.Header.Title, 'MailGuard');
    assert.equal(card.children[0].children.length, 1);
    const summary = card.children[0].children[0];
    assert.ok(summary.Text.includes('<b>\u2066' + score + ' / 100\u2069</b>'));
    assert.ok(summary.Text.includes(verdict));
    assert.equal(summary.BottomLabel, '\u2066Confidence: Medium\u2069');
    if (count) {
      assert.equal(card.children[1].Header, 'Why was this flagged?');
      assert.equal(card.children[1].children.length, count);
      assert.equal(card.children[1].children[0].Text, '\u2066Reason 25\u2069');
    } else {
      assert.equal(card.children.length, 3);
      assert.ok(!JSON.stringify(card).includes('Why was this flagged?'));
    }
    const action = card.children.at(-2).children[0];
    assert.equal(action.TopLabel, 'Recommended Action');
    assert.equal(action.StartIcon.Icon, 'DESCRIPTION');
    assert.equal(action.Text, '<b>\u2066Verify the sender.\u2069</b>');
    const details = card.children.at(-1);
    assert.equal(details.Header, 'Analysis details');
    assert.equal(details.Collapsible, true);
    assert.equal(details.NumUncollapsibleWidgets, 0);
    assert.ok(details.children.some(item => item.Text.includes('not a probability')));
    if (count) assert.ok(details.children.some(item => item.Text.includes('Reason 5')));
    assert.ok(!/<(?:style|div|span|h1)|style=|size=/.test(JSON.stringify(card)));
  });
}

test('weak signals remain in collapsed details and empty reasons stay hidden', () => {
  const { ctx } = setup();
  const card = ctx.buildResultCard({score:1, verdict:'Low Risk', confidence:'Low', confidence_explanation:'Limited evidence.',
    recommended_action:'Stay cautious.', limitations:[], signals:[{id:'url_long',points:1,explanation:'Long tracking link.'}]});
  assert.equal(card.children.length, 3);
  assert.ok(card.children.at(-1).children.some(item => item.Text.includes('Long tracking link.')));
  assert.equal(ctx.onHomepage()[0].children[0].children[0].Text, 'MailGuard - Open an email to analyze it');
  assert.ok(!/[^\x00-\x7F]/.test(source));
});

test('Safe Browsing match is first, with Google attribution only for that signal', () => {
  const {ctx}=setup();
  const result={score:90,verdict:'High Risk',confidence:'Medium',confidence_explanation:'Evidence.',recommended_action:'Verify.',limitations:[],
    reputation:{status:'match',checked_count:1,partial:false},
    signals:[{id:'urgency_language',points:5,explanation:'Urgent.'},{id:'safe_browsing_threat',points:70,explanation:'Match.'}]};
  let card=ctx.buildResultCard(result);
  assert.ok(card.children[1].children[0].Text.includes('Google Safe Browsing'));
  assert.ok(card.children[1].children.at(-1).Text.includes('Advisory provided by Google'));
  result.signals.shift();
  result.signals=[];result.reputation.status='unavailable';
  card=ctx.buildResultCard(result);
  assert.ok(!JSON.stringify(card).includes('Advisory provided by Google'));
  assert.ok(JSON.stringify(card).includes('Link reputation: Check unavailable.'));
});


for (const [status, expected] of [
  ['no_match', 'Link reputation: Checked - no known threat match.'],
  ['match', 'Link reputation: Known threat detected.'],
  ['no_urls', 'Link reputation: No links to check.'],
  ['unavailable', 'Link reputation: Check unavailable.'],
  ['timeout', 'Link reputation: Check unavailable.'],
  ['not_checked', 'Link reputation: Check unavailable.']
]) {
  test('Analysis details displays reputation status: ' + status, () => {
    const {ctx}=setup();
    const card=ctx.buildResultCard({score:0,verdict:'Low Risk',confidence:'Low',
      confidence_explanation:'Limited evidence.',recommended_action:'Stay cautious.',limitations:[],signals:[],
      reputation:{status,checked_count:0,partial:true}});
    const details=card.children.at(-1);
    assert.equal(details.Header,'Analysis details');
    assert.equal(details.Collapsible,true);
    assert.ok(details.children.some(item => item.Text === '\u2066'+expected+'\u2069'));
    assert.ok(details.children.some(item => item.Text.includes('first 50 distinct URLs')));
  });
}


test('Analysis details explains link checking without implying website visits', () => {
  const {ctx}=setup();
  const card=ctx.buildResultCard({score:1,verdict:'Low Risk',confidence:'Low',confidence_explanation:'Limited evidence.',
    recommended_action:'Stay cautious.',limitations:[],signals:[{id:'url_long',points:1,explanation:'Long link.'}]});
  const text=JSON.stringify(card.children.at(-1));
  for (const expected of ['How links are checked','checks URL structure','Google Safe Browsing',
    'never opens or fetches destination websites','Attachment contents are not scanned.','Additional signals']) {
    assert.ok(text.includes(expected));
  }
  assert.ok(!text.includes('Other signals'));
});
