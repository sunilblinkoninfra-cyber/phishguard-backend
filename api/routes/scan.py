from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Optional
import re  # For heuristic regex

router = APIRouter(prefix="/scan", tags=["scan"])

class ScanRequest(BaseModel):
    body: str

class ScanResponse(BaseModel):
    is_phishy: bool
    threats: list[str]
    scan_method: str
    risk_score: float

@router.post("/email", response_model=ScanResponse)
async def scan_email(request: ScanRequest, x_api_key: str = Header(None)):
    if x_api_key != "test-key-123":  # Stub auth
        raise HTTPException(status_code=401, detail="Invalid API key")

    # Heuristic scan (MVP – no DB/ClamAV)
    body = request.body.lower()
    threats = []
    risk = 0.0

    # Simple regex for phish flags
    if re.search(r'click here|free money|urgent|your account suspended', body):
        threats.append("suspicious_phrases")
        risk += 0.4
    if re.search(r'bit\.ly|tinyurl|short\.link', body):
        threats.append("shortened_links")
        risk += 0.3
    if re.search(r'bank|paypal|amazon', body) and re.search(r'login|password', body):
        threats.append("brand_impersonation")
        risk += 0.3

    is_phishy = risk > 0.5
    return ScanResponse(
        is_phishy=is_phishy,
        threats=threats,
        scan_method="heuristic",
        risk_score=risk
    )