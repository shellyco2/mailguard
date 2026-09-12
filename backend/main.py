"""Run from this folder: python -m uvicorn main:app --reload."""
import os
import secrets
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from models import AnalysisResult, EmailInput
from scoring import analyze
from reputation import check_urls, add_reputation

app = FastAPI(title="MailGuard", version="0.4.0")


def require_api_key(x_mailguard_key: str = Header(default="")) -> None:
    expected = os.environ.get("MAILGUARD_API_KEY", "")
    if not expected:
        # Local experiments need no key; hosted deployments must have one.
        if os.environ.get("K_SERVICE") or os.environ.get("VERCEL"):
            raise HTTPException(503, "Backend API key is not configured.")
        return
    if not secrets.compare_digest(x_mailguard_key.encode(), expected.encode()):
        raise HTTPException(401, "Invalid API key.")


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    # Pydantic's default error can include the rejected email text. Omit it.
    return JSONResponse(status_code=422, content={"detail": "Invalid email payload or size limit exceeded."})


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalysisResult, dependencies=[Depends(require_api_key)])
async def analyze_email(email: EmailInput):
    return add_reputation(analyze(email), await check_urls(email.urls))
