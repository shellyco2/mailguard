/** Builds the card shown when MailGuard opens in Gmail. */
function onHomepage() {
  const message = CardService.newTextParagraph()
    .setText('MailGuard - Open an email to analyze it');

  const section = CardService.newCardSection()
    .addWidget(message);

  const card = CardService.newCardBuilder()
    .addSection(section)
    .build();

  // A homepage trigger returns a list of cards, even when there is only one.
  return [card];
}

/** Gmail calls this when an email opens while MailGuard is active. */
function onGmailMessageOpen(e) {
  // Running this manually in the editor does not supply a Gmail event.
  if (!e || !e.gmail || !e.gmail.messageId || !e.gmail.accessToken) {
    return onHomepage();
  }

  // The event token grants temporary access to this message's metadata.
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  const message = GmailApp.getMessageById(e.gmail.messageId);

  const section = CardService.newCardSection()
    .addWidget(messageField('Sender', message.getFrom() || '(Unknown sender)'));

  // Read the actual header so it is omitted when no Reply-To is supplied.
  const replyTo = message.getHeader('Reply-To');
  if (replyTo && replyTo.trim()) {
    section.addWidget(messageField('Reply-To', replyTo));
  }

  section.addWidget(messageField('Subject', message.getSubject() || '(No subject)'));
  section.addWidget(CardService.newTextParagraph().setText(
    'Analyze Email sends message text, headers, and links to your MailGuard backend. Attachments are not inspected or sent. Up to 50 URLs are shared with Google Safe Browsing, whose results can be incomplete or incorrect.'));
  section.addWidget(CardService.newTextButton()
    .setText('Analyze Email')
    .setOnClickAction(CardService.newAction()
      .setFunctionName('onAnalyzeEmail')));

  return [CardService.newCardBuilder()
    .addSection(section)
    .build()];
}

/** Builds a labeled field that wraps long values in Gmail's narrow sidebar. */
function messageField(label, value) {
  return CardService.newDecoratedText()
    .setTopLabel(escapeCardText(label))
    .setText(escapeCardText(value))
    .setWrapText(true);
}

/** Display email headers as text, not CardService HTML formatting. */
function escapeCardText(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

/** Runs only after the user clicks Analyze Email. */
function onAnalyzeEmail(e) {
  const settings = PropertiesService.getScriptProperties();
  const backendUrl = (settings.getProperty('MAILGUARD_BACKEND_URL') || 'https://mailguard-api.vercel.app').replace(/\/$/, '');
  const apiKey = settings.getProperty('MAILGUARD_API_KEY');
  if (!backendUrl || !apiKey) {
    return analysisNotice('The analysis backend is not connected yet.');
  }
  if (!/^https:\/\/[a-z0-9.-]+(?::443)?$/i.test(backendUrl)) {
    return analysisNotice('Configure a valid HTTPS backend origin without a path.');
  }
  if (!e || !e.gmail || !e.gmail.messageId || !e.gmail.accessToken) {
    return analysisNotice('Reopen this email and click Analyze Email again.');
  }

  try {
    const email = extractEmail(e);
    const response = UrlFetchApp.fetch(backendUrl + '/analyze', {
      method: 'post',
      contentType: 'application/json',
      headers: { 'X-MailGuard-Key': apiKey },
      payload: JSON.stringify(email),
      muteHttpExceptions: true,
      followRedirects: false
    });
    if (response.getResponseCode() !== 200) {
      return analysisNotice('Analysis unavailable (HTTP ' + response.getResponseCode() + '). Check backend configuration and try again.');
    }
    const result = JSON.parse(response.getContentText());
    if (!validAnalysisResult(result)) {
      return analysisNotice('The backend returned an invalid result. No risk assessment was shown.');
    }
    return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().pushCard(buildResultCard(result)))
      .build();
  } catch (error) {
    // Do not log email content, tokens, or raw server errors.
    return analysisNotice('Could not analyze this email. Reopen it and retry. Check permissions, backend availability, and the documented message-size limits.');
  }
}

/** Extract the clicked message, never the first message of a thread. */
function extractEmail(e) {
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  const message = GmailApp.getMessageById(e.gmail.messageId);
  const body = message.getPlainBody();
  const html = message.getBody();
  if (body.length > 100000 || html.length > 1000000) {
    throw new Error('Message exceeds demo size limits.');
  }
  const email = {
    sender: message.getFrom(),
    reply_to: message.getHeader('Reply-To') || '',
    subject: message.getSubject(),
    body: body,
    urls: extractUrls(body, html),
    authentication_results: message.getHeader('Authentication-Results') || '',
    attachments: [] // Attachment inspection is outside this milestone.
  };
  if (email.sender.length > 2000 || email.reply_to.length > 2000 ||
      email.subject.length > 4000 || email.authentication_results.length > 20000) {
    throw new Error('Header exceeds demo size limits.');
  }
  return email;
}

/** Best-effort HTTP(S) links in text and HTML hrefs; never fetch any link. */
function extractUrls(body, html) {
  const urls = new Set();
  function add(value) {
    let url = decodeHtmlEntities(value.trim());
    if (/^www\./i.test(url)) url = 'https://' + url;
    if (url.indexOf('//') === 0) url = 'https:' + url;
    if (!/^https?:\/\//i.test(url)) return;
    if (url.length > 4096) throw new Error('URL exceeds demo limits.');
    urls.add(url);
    if (urls.size > 200) throw new Error('Too many URLs.');
  }
  // Quoted/unquoted href values include links hidden behind "click here".
  const hrefPattern = /\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi;
  let match;
  while ((match = hrefPattern.exec(html)) !== null) add(match[1] || match[2] || match[3] || '');
  const textPattern = /(?:https?:\/\/|www\.)[^\s<>"']+/gi;
  (body.match(textPattern) || []).forEach(function (value) {
    add(value.replace(/[.,;!?)\]]+$/, ''));
  });
  return Array.from(urls);
}

function decodeHtmlEntities(value) {
  const named = { amp: '&', quot: '"', apos: "'", lt: '<', gt: '>', colon: ':', sol: '/' };
  return value.replace(/&(#x[0-9a-f]+|#\d+|amp|quot|apos|lt|gt|colon|sol);/gi, function (entity, code) {
    if (code.charAt(0) !== '#') return named[code.toLowerCase()];
    const number = code.charAt(1).toLowerCase() === 'x' ? parseInt(code.slice(2), 16) : parseInt(code.slice(1), 10);
    return number > 0 && number <= 0x10ffff ? String.fromCodePoint(number) : entity;
  });
}

function validAnalysisResult(result) {
  return result && Number.isInteger(result.score) && result.score >= 0 && result.score <= 100 &&
    ['Low Risk', 'Moderate Risk', 'Suspicious', 'High Risk'].indexOf(result.verdict) !== -1 &&
    ['Low', 'Medium', 'High'].indexOf(result.confidence) !== -1 &&
    typeof result.confidence_explanation === 'string' && result.confidence_explanation.length <= 2000 &&
    typeof result.recommended_action === 'string' && result.recommended_action.length <= 2000 &&
    Array.isArray(result.signals) && result.signals.length <= 20 && result.signals.every(function (signal) {
      return typeof signal.id === 'string' && Number.isInteger(signal.points) && signal.points >= 0 &&
        typeof signal.explanation === 'string' && signal.explanation.length <= 2000;
    }) && Array.isArray(result.limitations) && result.limitations.length <= 10 && result.limitations.every(function (item) {
      return typeof item === 'string' && item.length <= 2000;
    });
}

/** Short display copy only; signal weights and backend responses stay unchanged. */
function reasonText(signal) {
  const labels = {
    safe_browsing_threat: 'Google Safe Browsing flags a link as a known potential threat.',
    authentication_failure: 'Identity checks failed; forwarding can also cause this.',
    authentication_uncertain: 'An identity check was inconclusive.',
    reply_to_mismatch: 'Replies go to another domain, sometimes legitimately.',
    url_ip_host: 'A link uses an IP address instead of a website name.',
    url_userinfo: 'Text before @ can disguise a link destination.',
    url_punycode: 'An internationalized domain could imitate a familiar name.',
    url_misleading_domain: "A different website embeds the sender's domain in its name.",
    url_unusual_host: 'A link has an unusually complex website name.',
    url_account_path: 'A concerning link leads to an account or sign-in page.',
    urgency_language: 'The message pressures you to act quickly.',
    credential_language: 'The message requests account verification or credentials.',
    financial_language: 'The message requests money or banking information.',
    language_combination: 'Pressure, account requests, or money requests appear together.'
  };
  return labels[signal.id] || signal.explanation;
}

/** Isolate English result text in RTL Gmail without changing message headers. */
function resultText(text) {
  return '\u2066' + escapeCardText(text) + '\u2069';
}

function buildResultCard(result) {
  const colors = {
    'Low Risk': '#137333', 'Moderate Risk': '#805500',
    'Suspicious': '#B06000', 'High Risk': '#B3261E'
  };
  const color = colors[result.verdict];
  // CardService controls font size; bold and native labels establish hierarchy.
  const summary = CardService.newDecoratedText()
    .setTopLabel('Risk score')
    .setText('<b>' + resultText(result.score + ' / 100') + '</b><br>' +
      '<font color="' + color + '"><b>' + resultText(result.verdict) + '</b></font>')
    .setBottomLabel('\u2066Confidence: ' + result.confidence + '\u2069')
    .setWrapText(true);
  const card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('MailGuard'))
    .addSection(CardService.newCardSection().addWidget(summary));

  const detailed = result.verdict === 'Suspicious' || result.verdict === 'High Risk';
  const ranked = result.signals.slice().sort(function (a, b) { return b.points - a.points; });
  const reasons = ranked.filter(function (signal) { return signal.points >= 5; })
    .slice(0, detailed ? 3 : 2);
  if (reasons.length) {
    const section = CardService.newCardSection().setHeader('Why was this flagged?');
    reasons.forEach(function (signal) {
      section.addWidget(CardService.newTextParagraph().setText(resultText(reasonText(signal))));
    });
    if (reasons.some(function (signal) { return signal.id === 'safe_browsing_threat'; })) {
      section.addWidget(CardService.newTextParagraph().setText(
        '<a href="https://safebrowsing.google.com/">Advisory provided by Google</a><br>' +
        'Results can be incomplete or incorrect. ' +
        '<a href="https://developers.google.com/safe-browsing/reference/Appropriate.Usage">About these threats</a>'));
    }
    card.addSection(section);
  }
  // Native section separators and an icon emphasize the action without a fake button.
  card.addSection(CardService.newCardSection().addWidget(CardService.newDecoratedText()
    .setTopLabel('Recommended Action')
    .setStartIcon(CardService.newIconImage().setIcon(CardService.Icon.DESCRIPTION))
    .setText('<b>' + resultText(result.recommended_action) + '</b>')
    .setWrapText(true)));

  const details = CardService.newCardSection().setHeader('Analysis details')
    .setCollapsible(true).setNumUncollapsibleWidgets(0)
    .addWidget(CardService.newTextParagraph().setText(resultText(
      'Rule-based score, not a probability or a guarantee of safety.')))
    .addWidget(CardService.newTextParagraph().setText('<b>How links are checked</b><br>' +
      resultText('MailGuard checks URL structure and sends up to 50 URLs to Google Safe Browsing for reputation checks. It never opens or fetches destination websites.')))
    .addWidget(CardService.newTextParagraph().setText(resultText('Attachment contents are not scanned.')))
    .addWidget(CardService.newTextParagraph().setText(resultText(result.confidence_explanation)));
  if (result.reputation) {
    const status = result.reputation.status;
    const messages = {
      match: 'Link reputation: Known threat detected.',
      no_match: 'Link reputation: Checked - no known threat match.',
      unavailable: 'Link reputation: Check unavailable.',
      timeout: 'Link reputation: Check unavailable.',
      no_urls: 'Link reputation: No links to check.'
    };
    const message = messages[status] || 'Link reputation: Check unavailable.';
    details.addWidget(CardService.newTextParagraph().setText(resultText(message)));
    if (result.reputation.partial) details.addWidget(CardService.newTextParagraph()
      .setText(resultText('Only the first 50 distinct URLs were selected for reputation checking.')));
  }
  // Preserve secondary evidence on demand without repeating the top reasons.
  const secondary = ranked.filter(function (signal) { return reasons.indexOf(signal) === -1; });
  if (secondary.length) {
    details.addWidget(CardService.newTextParagraph().setText('<b>Additional signals</b>'));
    secondary.forEach(function (signal) {
      details.addWidget(CardService.newTextParagraph().setText(resultText(reasonText(signal))));
    });
  }
  card.addSection(details);
  return card.build();
}

function analysisNotice(text) {
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText(text)).build();
}
