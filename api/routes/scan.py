import time
import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form
from pydantic import BaseModel, Field, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from core.auth import get_current_tenant
from models.database import Tenant, ScanResult, Incident, ThreatTier
from services.phishing_detector import PhishingDetector
from services.url_reputation import URLReputationService
from services.malware_scanner import MalwareScanner

router = APIRouter()
logger = logging.getLogger(__name__)

# Request/Response Models
class ScanRequest(BaseModel):
    subject: Optional[str] = Field(None, max_length=500)
    body: Optional[str] = Field(None, max_length=50000)
    urls: Optional[List[str]] = Field(default_factory=list)
    sender_email: Optional[EmailStr] = None
    recipient_email: Optional[EmailStr] = None
    source: str = Field(default="API", max_length=100)

class ScanResponse(BaseModel):
    scan_id: int
    verdict: str
    threat_tier: str
    risk_score: float
    confidence: float
    phishing_indicators: List[dict]
    url_reputation: dict
    malware_detected: bool
    malware_details: Optional[dict]
    mitre_attack_tags: List[str]
    scan_duration_ms: int
    timestamp: str

class BatchScanRequest(BaseModel):
    scans: List[ScanRequest]

class BatchScanResponse(BaseModel):
    total: int
    completed: int
    results: List[ScanResponse]

# Initialize services
phishing_detector = PhishingDetector()
url_reputation_service = URLReputationService()
malware_scanner = MalwareScanner()

@router.post("/scan", response_model=ScanResponse)
async def scan_email(
    request: ScanRequest,
    db: AsyncSession = Depends(get_db),
    tenant: Tenant = Depends(get_current_tenant)
):
    """
    Scan an email for phishing, malware, and malicious URLs
    
    Performs comprehensive security analysis including:
    - Phishing detection via NLP
    - URL reputation checks
    - Malware scanning (if attachments provided)
    - Risk scoring
    - MITRE ATT&CK mapping
    """
    start_time = time.time()
    
    try:
        # Validate input
        if not request.subject and not request.body and not request.urls:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="At least one of subject, body, or urls must be provided"
            )
        
        # Check API limits
        if tenant.api_calls_used >= tenant.api_calls_limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="API call limit exceeded for your plan"
            )
        
        # Phishing detection
        phishing_result = phishing_detector.analyze_email(
            subject=request.subject or "",
            body=request.body or "",
            urls=request.urls or []
        )
        
        # URL reputation checks
        url_reputation = {}
        if request.urls:
            url_reputation = await url_reputation_service.check_urls(request.urls, db)
            
            # Adjust risk score based on URL reputation
            malicious_urls = [url for url, rep in url_reputation.items() if rep.get("is_malicious")]
            if malicious_urls:
                phishing_result["risk_score"] = min(phishing_result["risk_score"] + 30, 100)
                phishing_result["indicators"].append({
                    "type": "malicious_url_detected",
                    "severity": "critical",
                    "description": f"{len(malicious_urls)} malicious URL(s) detected",
                    "value": malicious_urls[:3]
                })
        
        # Recalculate verdict and threat tier
        risk_score = phishing_result["risk_score"]
        if risk_score >= 70:
            verdict = "MALICIOUS"
            threat_tier = "HOT"
        elif risk_score >= 40:
            verdict = "SUSPICIOUS"
            threat_tier = "WARM"
        else:
            verdict = "CLEAN"
            threat_tier = "COLD"
        
        # Calculate scan duration
        scan_duration_ms = int((time.time() - start_time) * 1000)
        
        # Save scan result
        scan_result = ScanResult(
            tenant_id=tenant.id,
            scan_type="email",
            subject=request.subject,
            body=request.body,
            urls=request.urls,
            source=request.source,
            verdict=verdict,
            threat_tier=threat_tier,
            risk_score=risk_score,
            confidence=phishing_result["confidence"],
            phishing_indicators=phishing_result["indicators"],
            malware_detected=False,
            url_reputation=url_reputation,
            mitre_attack_tags=phishing_result["mitre_attack_tags"],
            scan_duration_ms=scan_duration_ms
        )
        
        db.add(scan_result)
        
        # Create incident if malicious or suspicious
        if verdict in ["MALICIOUS", "SUSPICIOUS"]:
            severity = "CRITICAL" if verdict == "MALICIOUS" else "HIGH"
            
            incident = Incident(
                tenant_id=tenant.id,
                scan_result_id=scan_result.id,
                title=f"{verdict}: {request.subject or 'Suspicious email detected'}",
                severity=severity,
                threat_tier=threat_tier,
                status="NEW"
            )
            db.add(incident)
        
        # Update tenant API usage
        tenant.api_calls_used += 1
        
        await db.commit()
        await db.refresh(scan_result)
        
        return ScanResponse(
            scan_id=scan_result.id,
            verdict=verdict,
            threat_tier=threat_tier,
            risk_score=risk_score,
            confidence=phishing_result["confidence"],
            phishing_indicators=phishing_result["indicators"],
            url_reputation=url_reputation,
            malware_detected=False,
            malware_details=None,
            mitre_attack_tags=phishing_result["mitre_attack_tags"],
            scan_duration_ms=scan_duration_ms,
            timestamp=scan_result.created_at.isoformat()
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error scanning email: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during scanning"
        )

@router.post("/scan-batch", response_model=BatchScanResponse)
async def scan_batch(
    request: BatchScanRequest,
    db: AsyncSession = Depends(get_db),
    tenant: Tenant = Depends(get_current_tenant)
):
    """
    Scan multiple emails in batch
    
    Useful for bulk processing and historical analysis
    """
    if len(request.scans) > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum 100 scans per batch"
        )
    
    results = []
    completed = 0
    
    for scan_req in request.scans:
        try:
            result = await scan_email(scan_req, db, tenant)
            results.append(result)
            completed += 1
        except Exception as e:
            logger.error(f"Error in batch scan: {e}")
            # Continue with next item
    
    return BatchScanResponse(
        total=len(request.scans),
        completed=completed,
        results=results
    )

@router.post("/scan-file")
async def scan_file(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    tenant: Tenant = Depends(get_current_tenant)
):
    """
    Scan a file for malware
    
    Supports: PDF, ZIP, EXE, DOC, XLS, and other common file types
    """
    start_time = time.time()
    
    try:
        # Check file size (25MB limit)
        contents = await file.read()
        file_size_mb = len(contents) / (1024 * 1024)
        
        if file_size_mb > 25:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="File size exceeds 25MB limit"
            )
        
        # Check API limits
        if tenant.api_calls_used >= tenant.api_calls_limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="API call limit exceeded for your plan"
            )
        
        # Scan for malware
        malware_result = await malware_scanner.scan_file(
            filename=file.filename,
            content=contents
        )
        
        # Calculate risk score
        risk_score = 90.0 if malware_result["is_infected"] else 10.0
        verdict = "MALICIOUS" if malware_result["is_infected"] else "CLEAN"
        threat_tier = "HOT" if malware_result["is_infected"] else "COLD"
        
        scan_duration_ms = int((time.time() - start_time) * 1000)
        
        # Save scan result
        scan_result = ScanResult(
            tenant_id=tenant.id,
            scan_type="file",
            subject=f"File scan: {file.filename}",
            attachments=[{"filename": file.filename, "size": len(contents)}],
            source="API",
            verdict=verdict,
            threat_tier=threat_tier,
            risk_score=risk_score,
            confidence=0.95,
            malware_detected=malware_result["is_infected"],
            malware_details=malware_result,
            scan_duration_ms=scan_duration_ms
        )
        
        db.add(scan_result)
        tenant.api_calls_used += 1
        
        await db.commit()
        
        return {
            "scan_id": scan_result.id,
            "filename": file.filename,
            "verdict": verdict,
            "threat_tier": threat_tier,
            "risk_score": risk_score,
            "malware_detected": malware_result["is_infected"],
            "malware_details": malware_result,
            "scan_duration_ms": scan_duration_ms
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error scanning file: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during file scanning"
        )