"""FastAPI backend for the Suspicious Message Checker web application."""

from __future__ import annotations

from collections import defaultdict, deque
import hashlib
import logging
import os
from pathlib import Path
import re
import threading
import time
from typing import Literal

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from google import genai
from google.genai import types
from pydantic import BaseModel, Field

# Load environment variables from .env at startup (never hardcode secrets).
load_dotenv()

logger = logging.getLogger("suspicious_message_checker")
logging.basicConfig(level=logging.INFO)

BASE_DIR = Path(__file__).resolve().parent
INDEX_HTML_PATH = BASE_DIR / "index.html"

app = FastAPI(title="Suspicious Message Checker", version="1.0.0")

MAX_MESSAGE_LENGTH = 1500
MAX_SENDER_LENGTH = 200
RATE_LIMIT_MAX_REQUESTS = 10
RATE_LIMIT_WINDOW_SECONDS = 60.0
CACHE_MAX_ENTRIES = 1024

PRIMARY_MODEL = "gemini-2.5-flash"
FALLBACK_MODEL = "gemini-2.5-flash-lite"
# Current-generation Flash-Lite replacement when legacy 2.5 models are retired for a key
# (per gemini-api-dev guidance, newer equivalents like gemini-3.5-flash-lite / gemini-4-hydrogen remain active).
ACTIVE_FALLBACK_MODEL = "gemini-3.5-flash-lite"

CategoryLiteral = Literal[
    "Manufactured Urgency",
    "Suspicious Link",
    "Credential Request",
    "Unofficial Channel",
    "Social Engineering",
]


class AnalyzeRequest(BaseModel):
    """Incoming payload for message safety inspection."""

    message: str
    claimed_sender: str = "Unspecified Sender"


class RedFlag(BaseModel):
    """A single verbatim warning indicator detected in the message."""

    exact_quote: str
    category: CategoryLiteral
    explanation: str


class AnalysisResponse(BaseModel):
    """Structured safety assessment returned to the UI."""

    risk_level: Literal["High", "Medium", "Low"]
    risk_score: int = Field(..., ge=0, le=100)
    claimed_sender: str
    summary: str
    analysis_engine: Literal[
        "AI + Heuristic Verified",
        "Deterministic Heuristic Mode",
    ]
    red_flags: list[RedFlag]
    safe_verification_steps: list[str]


# Thread-safe in-memory SHA-256 response cache and sliding-window rate limiter.
_cache_lock = threading.Lock()
ANALYSIS_CACHE: dict[str, AnalysisResponse] = {}

_rate_lock = threading.Lock()
IP_REQUEST_TIMESTAMPS: dict[str, deque[float]] = defaultdict(deque)


HEURISTIC_RULES: list[tuple[CategoryLiteral, int, re.Pattern[str], str]] = [
    (
        "Suspicious Link",
        40,
        re.compile(
            r"(?:https?://)?(?:www\.)?"
            r"(?:bit\.ly|tinyurl\.com|t\.co|rb\.gy|is\.gd|cutt\.ly|rebrand\.ly|shorturl\.at|ow\.ly)"
            r"/[^\s<>\"']+",
            re.IGNORECASE,
        ),
        "Uses a shortened URL that hides the true destination website before you click.",
    ),
    (
        "Suspicious Link",
        35,
        re.compile(
            r"(?:https?://|www\.)[a-z0-9-]+-"
            r"(?:verify|secure|login|signin|update|alert|account|support|bank|billing|refund|confirm)"
            r"[a-z0-9.-]*\.[a-z]{2,}(?:/[^\s<>\"']*)?",
            re.IGNORECASE,
        ),
        "Uses a hyphenated lookalike web address designed to imitate an official portal.",
    ),
    (
        "Suspicious Link",
        28,
        re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE),
        "Includes an external link inside an unsolicited alert—official services recommend opening their app or website directly instead.",
    ),
    (
        "Suspicious Link",
        35,
        re.compile(
            r"\b[a-z0-9-]+-"
            r"(?:verify|secure|login|signin|update|alert|account|support|bank|billing|refund|confirm)"
            r"[a-z0-9-]*\.[a-z]{2,}(?:/[^\s<>\"']*)?",
            re.IGNORECASE,
        ),
        "References a hyphenated lookalike domain often used in phishing campaigns.",
    ),
    (
        "Unofficial Channel",
        32,
        re.compile(
            r"\b[A-Za-z0-9._%+-]+@"
            r"(?:gmail|yahoo|hotmail|outlook|live|aol|icloud|protonmail|proton|gmx|mail)\.[A-Za-z.]{2,}\b",
            re.IGNORECASE,
        ),
        "Points to a free consumer email address rather than an organization's official domain.",
    ),
    (
        "Unofficial Channel",
        26,
        re.compile(
            r"\b(?:reach\s+out|contact\s+us|message\s+us|reply|chat)\s+(?:on|via|through)\s+"
            r"(?:WhatsApp|Telegram|Signal|Discord)\b",
            re.IGNORECASE,
        ),
        "Attempts to move the conversation onto an unofficial chat app where support identity cannot be verified.",
    ),
    (
        "Credential Request",
        40,
        re.compile(
            r"\b(?:\d{4,8}[- ]digit\s+(?:OTP\s+)?(?:verification\s+|security\s+)?code"
            r"|one-time\s+(?:password|passcode|code|pin)"
            r"|OTP(?:\s+(?:verification\s+)?code)?"
            r"|2FA\s+code"
            r"|verification\s+code"
            r"|security\s+code"
            r"|(?:your|account)\s+password"
            r"|ATM\s+PIN|PIN\s+number"
            r"|CVV|social\s+security\s+number|SSN"
            r"|credit\s+card\s+number|bank\s+account\s+number)\b",
            re.IGNORECASE,
        ),
        "Asks for a one-time passcode, password, or private account identifier that legitimate organizations never ask you to share.",
    ),
    (
        "Social Engineering",
        42,
        re.compile(
            r"\b(?:AnyDesk|TeamViewer|UltraViewer|RustDesk|ScreenConnect|Quick\s*Assist|LogMeIn|Supremo|RemotePC)\b",
            re.IGNORECASE,
        ),
        "Asks you to install remote desktop software, which would hand over full control of your device and open sessions.",
    ),
    (
        "Social Engineering",
        40,
        re.compile(
            r"\b(?:Apple\s+gift\s+card|Google\s+Play\s+(?:gift\s+)?card|Steam\s+(?:gift\s+)?card"
            r"|gift\s+cards?|Bitcoin|BTC|Ethereum|USDT|crypto(?:currency)?"
            r"|wire\s+transfer|Western\s+Union|MoneyGram|Zelle\s+payment)\b",
            re.IGNORECASE,
        ),
        "Requests payment via gift cards, cryptocurrency, or irreversible transfers—a strong scam indicator.",
    ),
    (
        "Social Engineering",
        24,
        re.compile(
            r"\b(?:unauthorized\s+(?:purchase|charge|transaction)(?:\s+of\s+\$[\d,]+(?:\.\d{2})?)?"
            r"|won\s+a\s+(?:prize|lottery|reward)|arrest\s+warrant|tax\s+penalty)\b",
            re.IGNORECASE,
        ),
        "Introduces an alarming fake charge, legal threat, or unexpected windfall to trigger an emotional reaction.",
    ),
    (
        "Manufactured Urgency",
        24,
        re.compile(
            r"\b(?:within\s+\d+\s+(?:hours?|minutes?|hrs?|mins?)"
            r"|temporarily\s+(?:frozen|locked|suspended)"
            r"|permanently\s+(?:suspended|closed|locked)"
            r"|permanent\s+account\s+closure"
            r"|account\s+(?:closure|suspension|termination)"
            r"|final\s+notice"
            r"|act\s+now"
            r"|urgent\s+action\s+required"
            r"|cancel\s+this\s+charge\s+immediately"
            r"|suspicious\s+activity"
            r"|unusual\s+activity"
            r"|URGENT"
            r"|immediately)\b",
            re.IGNORECASE,
        ),
        "Creates artificial urgency or threatens account loss so you act quickly without double-checking.",
    ),
]

PUBLIC_EMAIL_IN_SENDER_RE = re.compile(
    r"@[A-Za-z0-9.-]*\b(?:gmail|yahoo|hotmail|outlook|live|aol|icloud|protonmail|proton)\.[A-Za-z.]{2,}\b",
    re.IGNORECASE,
)

OFFICIAL_BRAND_HINT_RE = re.compile(
    r"\b(?:bank|chase|wells\s*fargo|citi|apple|microsoft|google|paypal|amazon|irs|gov|support|security|fraud|billing|ups|fedex|usps)\b",
    re.IGNORECASE,
)

HIGH_RISK_LINK_HINT_RE = re.compile(
    r"(?:verify|secure|login|signin|update|alert|account|support|unlock|confirm|billing|"
    r"\.(?:xyz|top|click|buzz|loan|support|tk|ml)\b|https?://\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)


def _get_api_key() -> str | None:
    """Read GEMINI_API_KEY from environment dynamically without caching secrets in code."""
    key = (os.environ.get("GEMINI_API_KEY") or "").strip()
    if not key or key == "your_api_key_here":
        return None
    return key


def _extract_client_ip(request: Request) -> str:
    """Resolve client IP from X-Forwarded-For (Cloud Run proxy) or socket peer."""
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        first_hop = forwarded.split(",")[0].strip()
        if first_hop:
            return first_hop
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def _consume_rate_limit(client_ip: str) -> bool:
    """Return True if client IP is within the 10 req/min sliding window; False if exceeded."""
    now = time.monotonic()
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS
    with _rate_lock:
        timestamps = IP_REQUEST_TIMESTAMPS[client_ip]
        while timestamps and timestamps[0] <= cutoff:
            timestamps.popleft()
        if len(timestamps) >= RATE_LIMIT_MAX_REQUESTS:
            return False
        timestamps.append(now)
        return True


def _build_cache_key(message: str, claimed_sender: str) -> str:
    """Compute SHA-256 key over normalized message and claimed sender."""
    payload = f"{message.strip().lower()}\x00{claimed_sender.strip().lower()}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _get_cached_analysis(cache_key: str) -> AnalysisResponse | None:
    with _cache_lock:
        cached = ANALYSIS_CACHE.get(cache_key)
        return cached.model_copy(deep=True) if cached else None


def _store_cached_analysis(cache_key: str, response: AnalysisResponse) -> None:
    with _cache_lock:
        if cache_key not in ANALYSIS_CACHE and len(ANALYSIS_CACHE) >= CACHE_MAX_ENTRIES:
            oldest_key = next(iter(ANALYSIS_CACHE))
            ANALYSIS_CACHE.pop(oldest_key, None)
        ANALYSIS_CACHE[cache_key] = response.model_copy(deep=True)


def _trim_trailing_punctuation(text: str, start: int, end: int) -> tuple[int, int, str]:
    """Trim sentence-ending punctuation from URL matches while keeping exact text slice."""
    quote = text[start:end]
    while quote and quote[-1] in ".,;:!?)>\"'":
        end -= 1
        quote = text[start:end]
    return start, end, quote


def _spans_overlap(a_start: int, a_end: int, used_spans: list[tuple[int, int]]) -> bool:
    return any(not (a_end <= u_start or a_start >= u_end) for u_start, u_end in used_spans)


def _build_safe_steps(
    categories: set[CategoryLiteral],
    claimed_sender: str,
) -> list[str]:
    """Generate 3-4 concrete, plain-English safety verification steps."""
    steps: list[str] = []
    sender_label = (
        claimed_sender
        if claimed_sender != "Unspecified Sender"
        else "the organization"
    )

    if "Suspicious Link" in categories:
        steps.append(
            f"Do not tap or click links inside the message; open a fresh browser tab or the official {sender_label} mobile app to check your account."
        )
    if "Credential Request" in categories:
        steps.append(
            "Never share one-time passcodes (OTPs), passwords, or PINs—legitimate support staff will never ask you to read back a verification code."
        )
    if "Social Engineering" in categories:
        steps.append(
            "Refuse requests to install remote screen-sharing tools (like AnyDesk or TeamViewer) or send gift cards, wire transfers, or crypto."
        )
    if "Unofficial Channel" in categories or "Manufactured Urgency" in categories:
        steps.append(
            f"Verify directly by calling the official phone number printed on the back of your card, statement, or {sender_label}'s verified website."
        )

    fallback_pool = [
        f"Check your {sender_label} notifications directly inside the official app or website rather than replying to this message.",
        "Confirm the sender's full email domain or official short code before trusting any claim or request.",
        "Never share passwords, PINs, or one-time verification codes with anyone who contacts you unexpectedly.",
        "If anything still feels uncertain, pause and verify with a trusted family member or official customer support line.",
    ]
    for candidate in fallback_pool:
        if len(steps) >= 4:
            break
        if candidate not in steps:
            steps.append(candidate)

    return steps[:4]


def run_heuristic_scanner(message: str, claimed_sender: str) -> AnalysisResponse:
    """Step A: Deterministic regex/heuristic scan guaranteeing zero-downtime operation."""
    matched_spans: list[tuple[int, int]] = []
    findings: list[tuple[int, RedFlag, int]] = []

    for category, base_weight, pattern, explanation in HEURISTIC_RULES:
        for match in pattern.finditer(message):
            start, end = match.span()
            if category == "Suspicious Link":
                start, end, quote = _trim_trailing_punctuation(message, start, end)
            else:
                quote = match.group(0)

            if not quote or _spans_overlap(start, end, matched_spans):
                continue

            weight = base_weight
            rule_explanation = explanation
            if category == "Suspicious Link" and HIGH_RISK_LINK_HINT_RE.search(quote):
                weight = max(weight, 38)
                if "bit.ly" not in quote.lower() and "tinyurl" not in quote.lower():
                    rule_explanation = (
                        "Link contains phishing lure keywords or a high-risk domain pattern designed to look like an official security page."
                    )

            matched_spans.append((start, end))
            findings.append(
                (
                    start,
                    RedFlag(
                        exact_quote=quote,
                        category=category,
                        explanation=rule_explanation,
                    ),
                    weight,
                )
            )

    findings.sort(key=lambda item: item[0])
    red_flags = [item[1] for item in findings]
    detected_categories = {flag.category for flag in red_flags}

    sender_free_mail_mismatch = bool(
        PUBLIC_EMAIL_IN_SENDER_RE.search(claimed_sender)
        and OFFICIAL_BRAND_HINT_RE.search(claimed_sender)
    )

    if not red_flags and not sender_free_mail_mismatch:
        risk_score = 5
        risk_level: Literal["High", "Medium", "Low"] = "Low"
        summary = (
            "No urgent threats, suspicious links, or credential requests were found in this message. "
            "It reads like a routine informational notice, though verifying directly in an official app is always good practice."
        )
    else:
        raw_score = sum(item[2] for item in findings)
        if len(detected_categories) >= 3:
            raw_score += 10
        if sender_free_mail_mismatch:
            raw_score += 20
        risk_score = min(100, max(15, raw_score))

        if risk_score >= 60:
            risk_level = "High"
            summary = (
                "Strong warning signs suggest this message may be an impersonation or phishing attempt. "
                "Take a breath and verify directly through an official channel before clicking anything or replying."
            )
        elif risk_score >= 25:
            risk_level = "Medium"
            summary = (
                "This message contains elements commonly seen in scams, such as unverified links or urgent language. "
                "Confirm it independently through the organization's official website or phone number before acting."
            )
        else:
            risk_level = "Low"
            summary = (
                "Only minor cautionary cues were detected, with no direct credential or payment demands. "
                "You can still confirm the update safely by checking your official account directly."
            )

        if sender_free_mail_mismatch:
            summary += " Note that the claimed sender uses a free public email address while posing as an official brand."

    return AnalysisResponse(
        risk_level=risk_level,
        risk_score=risk_score,
        claimed_sender=claimed_sender,
        summary=summary,
        analysis_engine="Deterministic Heuristic Mode",
        red_flags=red_flags,
        safe_verification_steps=_build_safe_steps(detected_categories, claimed_sender),
    )


def _find_exact_substring(message: str, candidate: str) -> str | None:
    """Ensure a quote appears verbatim inside message, repairing casing if needed."""
    cleaned = candidate.strip()
    if not cleaned:
        return None
    if cleaned in message:
        return cleaned
    match = re.search(re.escape(cleaned), message, re.IGNORECASE)
    if match:
        return match.group(0)
    return None


def _reconcile_ai_result(
    ai_result: AnalysisResponse,
    message: str,
    claimed_sender: str,
    heuristic_result: AnalysisResponse,
) -> AnalysisResponse:
    """Validate AI verbatim quotes and combine with deterministic findings."""
    verified_flags: list[RedFlag] = []
    seen_quotes_lower: set[str] = set()

    for flag in ai_result.red_flags:
        verbatim = _find_exact_substring(message, flag.exact_quote)
        if not verbatim:
            continue
        lowered = verbatim.lower()
        if lowered in seen_quotes_lower:
            continue
        seen_quotes_lower.add(lowered)
        verified_flags.append(
            RedFlag(
                exact_quote=verbatim,
                category=flag.category,
                explanation=flag.explanation.strip() or "Flagged as a potential warning sign.",
            )
        )

    # Ensure deterministic regex catches are never silently dropped by the LLM.
    for h_flag in heuristic_result.red_flags:
        h_lower = h_flag.exact_quote.lower()
        already_covered = any(
            h_lower in existing or existing in h_lower
            for existing in seen_quotes_lower
        )
        if not already_covered:
            seen_quotes_lower.add(h_lower)
            verified_flags.append(h_flag)

    # Keep flags ordered by first appearance in the message for clean inspection.
    verified_flags.sort(key=lambda item: message.find(item.exact_quote))

    # Never allow AI to under-score high-confidence deterministic threats.
    final_score = max(ai_result.risk_score, heuristic_result.risk_score)
    if not verified_flags and heuristic_result.risk_score <= 10:
        final_score = min(ai_result.risk_score, 20)
    final_score = max(0, min(100, final_score))

    if final_score >= 60:
        final_level: Literal["High", "Medium", "Low"] = "High"
    elif final_score >= 25:
        final_level = "Medium"
    else:
        final_level = "Low"

    steps = [s.strip() for s in ai_result.safe_verification_steps if s.strip()][:4]
    if len(steps) < 3:
        steps = heuristic_result.safe_verification_steps

    summary = ai_result.summary.strip() or heuristic_result.summary

    return AnalysisResponse(
        risk_level=final_level,
        risk_score=final_score,
        claimed_sender=claimed_sender,
        summary=summary,
        analysis_engine="AI + Heuristic Verified",
        red_flags=verified_flags,
        safe_verification_steps=steps,
    )


def _call_gemini_model(
    model_name: str,
    api_key: str,
    message: str,
    claimed_sender: str,
    heuristic_result: AnalysisResponse,
) -> AnalysisResponse:
    """Invoke Gemini structured output generation for a given model name."""
    client = genai.Client(
        api_key=api_key,
        http_options=types.HttpOptions(
            retry_options=types.HttpRetryOptions(attempts=1),
            timeout=15000,
        ),
    )

    heuristic_hints = (
        ", ".join(
            f"[{flag.category}] {flag.exact_quote!r}"
            for flag in heuristic_result.red_flags
        )
        or "None"
    )

    system_instruction = (
        "You are a calm, protective digital safety analyst helping everyday users spot phishing, "
        "smishing, and social engineering messages. Provide clear, reassuring, plain-English explanations. "
        "CRITICAL: Every `exact_quote` in `red_flags` MUST be an exact, character-for-character verbatim "
        "substring copied directly from the user's message text—never paraphrase, alter punctuation, or invent quotes. "
        "Include 3 to 4 concrete `safe_verification_steps` tailored to the claimed sender."
    )

    user_prompt = (
        f"Claimed Sender: {claimed_sender}\n"
        f"Pre-scan heuristic detections: {heuristic_hints}\n"
        f"Message to analyze:\n\"\"\"\n{message}\n\"\"\""
    )

    response = client.models.generate_content(
        model=model_name,
        contents=user_prompt,
        config=types.GenerateContentConfig(
            system_instruction=system_instruction,
            temperature=0.1,
            max_output_tokens=700,
            response_mime_type="application/json",
            response_schema=AnalysisResponse,
        ),
    )

    if isinstance(response.parsed, AnalysisResponse):
        parsed = response.parsed
    elif response.text:
        parsed = AnalysisResponse.model_validate_json(response.text)
    else:
        raise ValueError(f"Empty response from model {model_name}")

    return _reconcile_ai_result(parsed, message, claimed_sender, heuristic_result)


def analyze_message_pipeline(
    message: str,
    claimed_sender: str,
    allow_ai: bool,
) -> tuple[AnalysisResponse, bool]:
    """Run the 3-tier cascade (Heuristic -> Gemini cascade -> Deterministic Fallback).

    Returns (AnalysisResponse, should_cache).
    """
    # Step A: Always run deterministic scanner first.
    heuristic_result = run_heuristic_scanner(message, claimed_sender)

    api_key = _get_api_key()
    if not allow_ai or not api_key:
        return heuristic_result, (api_key is None)

    # Steps B & C: Cascade across primary, lite fallback, and active Flash-Lite replacement.
    for model_name in (PRIMARY_MODEL, FALLBACK_MODEL, ACTIVE_FALLBACK_MODEL):
        try:
            ai_result = _call_gemini_model(
                model_name,
                api_key,
                message,
                claimed_sender,
                heuristic_result,
            )
            return ai_result, True
        except Exception as exc:
            logger.warning(
                "Model %s failed (%s); trying next tier.",
                model_name,
                type(exc).__name__,
            )

    # Step D: Zero-downtime deterministic fallback (cached when AI was allowed).
    return heuristic_result, True


@app.get("/", include_in_schema=False)
async def serve_frontend() -> FileResponse:
    """Serve the single-page UI."""
    if not INDEX_HTML_PATH.exists():
        raise HTTPException(status_code=404, detail="Frontend index.html not found.")
    return FileResponse(INDEX_HTML_PATH)


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint for Cloud Run readiness."""
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalysisResponse)
@app.post("/api/analyze", response_model=AnalysisResponse, include_in_schema=False)
async def analyze_message(payload: AnalyzeRequest, request: Request) -> AnalysisResponse:
    """Analyze a suspicious message with SHA-256 caching, IP rate limiting, and 3-tier fallback."""
    cleaned_message = payload.message.strip()
    if not cleaned_message:
        raise HTTPException(
            status_code=400,
            detail="Please paste or select a message to analyze.",
        )

    # Cap incoming message length strictly at 1,500 chars to protect token budget.
    capped_message = cleaned_message[:MAX_MESSAGE_LENGTH]
    cleaned_sender = (
        payload.claimed_sender.strip()[:MAX_SENDER_LENGTH] or "Unspecified Sender"
    )

    cache_key = _build_cache_key(capped_message, cleaned_sender)
    cached = _get_cached_analysis(cache_key)
    if cached is not None:
        return cached

    client_ip = _extract_client_ip(request)
    within_rate_limit = _consume_rate_limit(client_ip)

    result, should_cache = analyze_message_pipeline(
        capped_message,
        cleaned_sender,
        allow_ai=within_rate_limit,
    )

    if should_cache:
        _store_cached_analysis(cache_key, result)

    return result
