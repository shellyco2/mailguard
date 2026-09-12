"""One bounded Safe Browsing v5 lookup; never request an email link itself."""
import asyncio
import hashlib
import logging
import os
import re
import time
from collections import OrderedDict

import httpx
from models import AnalysisResult, Signal
from scoring import verdict_for
from safe_browsing_wire import decode_response
from google.protobuf.message import DecodeError

ENDPOINT = 'https://safebrowsing.googleapis.com/v5/urls:search'
TIMEOUT_SECONDS = 3.0
MAX_URLS = 50
# Ephemeral per-worker cache: hashed batch identifiers, booleans and expirations only.
# Both matches and no-matches honor Google's cacheDuration, up to 30 minutes.
_cache = OrderedDict()
for logger in ('httpx', 'httpcore'):
    logging.getLogger(logger).setLevel(logging.WARNING)  # Never log query URLs.


async def check_urls(urls: list[str]) -> dict:
    unique = list(dict.fromkeys(urls))
    selected = unique[:MAX_URLS]
    partial = len(unique) > len(selected)
    result = {'status': 'not_checked', 'checked_count': 0, 'partial': partial}
    if not selected:
        result['status'] = 'no_urls'
        return result
    key = os.environ.get('SAFE_BROWSING_API_KEY', '')
    if not key:
        result['status'] = 'unavailable'
        return result
    cache_key = hashlib.sha256('\0'.join(sorted(selected)).encode()).digest()
    cached = _cache.get(cache_key)
    if cached and cached[0] > time.monotonic():
        _cache.move_to_end(cache_key)
        return dict(result, status=cached[1], checked_count=len(selected))

    async def lookup():
        async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS, follow_redirects=False) as client:
            response = await client.get(ENDPOINT, params=[('urls', url) for url in selected],
                                        headers={'X-Goog-Api-Key': key})
            response.raise_for_status()
            return decode_response(response.content)

    try:
        data = await asyncio.wait_for(lookup(), timeout=TIMEOUT_SECONDS)
        if not isinstance(data, dict) or not isinstance(data.get('threats', []), list):
            raise ValueError('Invalid response')
        threats = data.get('threats', [])
        if any(not isinstance(t, dict) or not isinstance(t.get('threatTypes'), list)
               or not t['threatTypes'] for t in threats):
            raise ValueError('Invalid threat')
        status = 'match' if threats else 'no_match'
        duration = data.get('cacheDuration', '')
        if not isinstance(duration, str) or not re.fullmatch(r'\d+(?:\.\d{1,9})?s', duration):
            raise ValueError('Missing cache duration')
        seconds = min(float(duration[:-1]), 1800)
        _cache[cache_key] = (time.monotonic() + seconds, status)
        _cache.move_to_end(cache_key)
        while len(_cache) > 128:
            _cache.popitem(last=False)
        return dict(result, status=status, checked_count=len(selected))
    except (TimeoutError, httpx.TimeoutException):
        return dict(result, status='timeout')
    except (httpx.HTTPError, ValueError, TypeError, KeyError, DecodeError):
        # Do not log exceptions: they can contain URLs or request headers.
        return dict(result, status='unavailable')


def add_reputation(result: AnalysisResult, reputation: dict) -> AnalysisResult:
    """Only a known match adds points; every other outcome preserves heuristics."""
    result = result.model_copy(deep=True)
    result.reputation = reputation
    if reputation['status'] == 'match':
        result.signals.insert(0, Signal(id='safe_browsing_threat', category='reputation', points=70,
            explanation='Google Safe Browsing flags a link as a known potential threat.'))
        result.category_scores['reputation'] = 70
        result.score = min(100, result.score + 70)
        result.verdict, result.recommended_action = verdict_for(result.score)
        # Apply the existing confidence thresholds to the additional evidence category.
        substantial = sum(value >= 8 for value in result.category_scores.values())
        strong = sum(value >= 20 for value in result.category_scores.values())
        result.confidence = 'High' if substantial >= 3 and strong >= 2 else 'Medium' if substantial >= 2 and strong >= 1 else 'Low'
    return result
