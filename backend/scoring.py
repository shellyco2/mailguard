"""Explainable evidence points, not a probability. No external lookups."""
import ipaddress
import re
from email.utils import parseaddr
from urllib.parse import unquote, urlsplit

from models import AnalysisResult, EmailInput, Signal

CATEGORY_CAPS = {"authentication": 30, "sender": 8, "urls": 45, "language": 30}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "buff.ly"}
LANGUAGE_RULES = {
    "urgency_language": (5, r"\b(urgent|immediately|act now|within 24 hours|final warning|account (?:will be )?suspended)\b", "The message pressures you to act quickly."),
    "credential_language": (10, r"\b(verify (?:your )?account|confirm (?:your )?password|enter (?:your )?password|login credentials)\b", "The message asks for account verification or credentials."),
    "financial_language": (10, r"\b(wire transfer|bank transfer|gift cards?|send (?:money|payment)|update (?:your )?bank details)\b", "The message requests money or banking information."),
}


def address_domain(address: str) -> str:
    parsed = parseaddr(address)[1]
    if "@" not in parsed:
        return ""
    try:
        return parsed.rsplit("@", 1)[1].lower().rstrip(".").encode("idna").decode("ascii")
    except UnicodeError:
        return ""


def verdict_for(score: int) -> tuple[str, str]:
    if score >= 70:
        return "High Risk", "Do not click links, open attachments, or provide credentials. Verify the sender through another channel."
    if score >= 45:
        return "Suspicious", "Avoid clicking links or sharing sensitive information until the sender is verified."
    if score >= 20:
        return "Moderate Risk", "Review the sender and links carefully before taking action."
    return "Low Risk", "No special action needed. Stay cautious with unexpected requests."


def analyze(email: EmailInput) -> AnalysisResult:
    candidates: dict[str, Signal] = {}

    def add(rule: str, category: str, points: int, explanation: str):
        # Repetition never earns more points.
        candidates.setdefault(rule, Signal(id=rule, category=category, points=points, explanation=explanation))

    auth = re.sub(r"\([^()]*\)", "", email.authentication_results.lower())
    methods = re.findall(r"(?:^|;)\s*(spf|dkim|dmarc)\s*=\s*(\w+)\b", auth)
    failures = {method for method, result in methods if result == "fail"}
    if failures:
        # One combined signal: SPF/DKIM failures often cause the same DMARC failure.
        points = 30 if "dmarc" in failures else 25 if {"spf", "dkim"} <= failures else 20
        if ("dmarc", "pass") in methods and "dmarc" not in failures:
            points = 5  # Forwarding can break SPF while aligned DKIM passes DMARC.
        add("authentication_failure", "authentication", points,
            "Email identity checks report a failure. Forwarding can sometimes cause this.")
    elif any(result in {"softfail", "permerror"} for _, result in methods):
        add("authentication_uncertain", "authentication", 8,
            "An email identity check was inconclusive or reported a soft failure.")

    sender = address_domain(email.sender)
    reply = address_domain(email.reply_to)
    if sender and reply and sender != reply:
        add("reply_to_mismatch", "sender", 8,
            "Replies go to a different domain. Mailing services can legitimately do this.")

    for url in sorted(set(email.urls)):
        try:
            parsed = urlsplit(url.strip())
            host = (parsed.hostname or "").lower().rstrip(".").encode("idna").decode("ascii")
            _ = parsed.port
            if parsed.scheme.lower() not in {"http", "https"} or not host or any(c.isspace() for c in host):
                raise ValueError()
        except (ValueError, UnicodeError):
            add("url_invalid", "urls", 2, "A link could not be interpreted reliably.")
            continue
        concerning = False
        try:
            ipaddress.ip_address(host)
            add("url_ip_host", "urls", 25, "A link uses a numeric IP address instead of a website name.")
            concerning = True
        except ValueError:
            pass
        if parsed.username is not None or parsed.password is not None:
            add("url_userinfo", "urls", 25, "A link uses text before @ that can hide its real destination.")
            concerning = True
        if any(label.startswith("xn--") for label in host.split(".")):
            add("url_punycode", "urls", 12, "A link uses an internationalized domain that could imitate another name.")
            concerning = True
        if sender and host.startswith(sender + "."):
            add("url_misleading_domain", "urls", 25, "A link puts the sender's domain inside a different website's name.")
            concerning = True
        labels = host.split(".")
        if len(labels) >= 6 or any(len(label) >= 40 or label.count("-") >= 4 for label in labels):
            add("url_unusual_host", "urls", 5, "A link has an unusually complex website name; this can also be legitimate.")
            concerning = True
        if concerning and re.search(r"(?:^|[/_.-])(login|signin|account|verify|password)(?:$|[/_.-])", unquote(parsed.path).lower()):
            add("url_account_path", "urls", 10, "A link with another warning sign leads to an account or sign-in page.")
        if host in SHORTENERS:
            add("url_shortener", "urls", 3, "A shortened link hides its final destination.")
        if parsed.scheme.lower() == "http":
            add("url_http", "urls", 2, "A link uses unencrypted HTTP; this alone is weak evidence.")
        if len(url) > 200:
            add("url_long", "urls", 1, "A link is long, as legitimate tracking links often are.")

    text = email.subject + "\n" + email.body
    matched = []
    for rule, (points, pattern, explanation) in LANGUAGE_RULES.items():
        if re.search(pattern, text, re.IGNORECASE):
            add(rule, "language", points, explanation)
            matched.append(rule)
    if len(matched) >= 2:
        add("language_combination", "language", 15,
            "Pressure, account requests, or money requests appear together.")

    # Keep the strongest reasons first. Each point shown is AFTER its category cap.
    totals = dict.fromkeys(CATEGORY_CAPS, 0)
    signals = []
    for signal in sorted(candidates.values(), key=lambda item: (-item.points, item.id)):
        points = min(signal.points, CATEGORY_CAPS[signal.category] - totals[signal.category])
        if points:
            signals.append(signal.model_copy(update={"points": points}))
            totals[signal.category] += points
    signals.sort(key=lambda item: (-item.points, item.id))
    score = min(100, sum(totals.values()))
    # Correlated rules within one category count as only one evidence source.
    substantial = sum(value >= 8 for value in totals.values())
    strong = sum(value >= 20 for value in totals.values())
    confidence = "High" if substantial >= 3 and strong >= 2 else "Medium" if substantial >= 2 and strong >= 1 else "Low"
    verdict, action = verdict_for(score)
    return AnalysisResult(
        score=score, verdict=verdict, confidence=confidence,
        confidence_explanation="Confidence describes the evidence, not email safety.",
        category_scores=totals, signals=signals, recommended_action=action,
        limitations=[
            "Rule-based score, not a probability or a guarantee of safety.",
            "Links are not visited. Attachments are not inspected, including filenames.",
        ])
