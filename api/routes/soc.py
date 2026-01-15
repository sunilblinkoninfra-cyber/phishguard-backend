import logging
from typing import List, Optional
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from core.auth import get_current_tenant
from models.database import Tenant, Incident, ScanResult, IncidentStatus

router = APIRouter()
logger = logging.getLogger(__name__)

# Response Models
class IncidentResponse(BaseModel):
    id: int
    title: str
    severity: str
    status: str
    threat_tier: str
    risk_score: float
    source: str
    detected_at: str
    updated_at: str
    phishing_indicators: List[dict]
    mitre_attack_tags: List[str]

class SOCMetricsResponse(BaseModel):
    total_alerts: int
    hot_count: int
    warm_count: int
    cold_count: int
    new_count: int
    investigating_count: int
    resolved_count: int
    detection_rate: float
    alerts_24h: List[dict]
    threat_distribution: dict
    severity_distribution: dict

class UpdateIncidentRequest(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    notes: Optional[str] = None
    resolution: Optional[str] = None

@router.get("/", response_model=List[IncidentResponse])
async def get_incidents(
    status: Optional[str] = Query(None, description="Filter by status"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    threat_tier: Optional[str] = Query(None, description="Filter by threat tier"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    tenant: Tenant = Depends(get_current_tenant)
):
    """
    Get all security incidents for the SOC dashboard
    
    Returns incidents sorted by severity and detection time
    """
    try:
        # Build query
        stmt = select(Incident, ScanResult).join(
            ScanResult, Incident.scan_result_id == ScanResult.id
        ).where(
            Incident.tenant_id == tenant.id
        )
        
        # Apply filters
        if status:
            stmt = stmt.where(Incident.status == status.upper())
        if severity:
            stmt = stmt.where(Incident.severity == severity.upper())
        if threat_tier:
            stmt = stmt.where(Incident.threat_tier == threat_tier.upper())
        
        # Order by severity and time
        severity_order = {
            "CRITICAL": 4,
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1
        }
        
        stmt = stmt.order_by(
            Incident.detected_at.desc()
        ).limit(limit).offset(offset)
        
        result = await db.execute(stmt)
        incidents_with_scans = result.all()
        
        # Format response
        response = []
        for incident, scan in incidents_with_scans:
            response.append(IncidentResponse(
                id=incident.id,
                title=incident.title,
                severity=incident.severity,
                status=incident.status,
                threat_tier=incident.threat_tier,
                risk_score=scan.risk_score,
                source=scan.source,
                detected_at=incident.detected_at.isoformat(),
                updated_at=incident.updated_at.isoformat(),
                phishing_indicators=scan.phishing_indicators or [],
                mitre_attack_tags=scan.mitre_attack_tags or []
            ))
        
        # Sort by severity
        response.sort(
            key=lambda x: (
                severity_order.get(x.severity, 0),
                x.detected_at
            ),
            reverse=True
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Error fetching incidents: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error fetching incidents"
        )

@router.get("/metrics", response_model=SOCMetricsResponse)
async def get_soc_metrics(
    db: AsyncSession = Depends(get_db),
    tenant: Tenant = Depends(get_current_tenant)
):
    """
    Get SOC dashboard metrics and statistics
    
    Returns:
    - Alert counts by threat tier
    - Status distribution
    - 24-hour trend data
    - Threat type distribution
    """
    try:
        # Total alerts
        total_stmt = select(func.count(Incident.id)).where(
            Incident.tenant_id == tenant.id
        )
        total_result = await db.execute(total_stmt)
        total_alerts = total_result.scalar() or 0
        
        # Threat tier distribution
        hot_stmt = select(func.count(Incident.id)).where(
            and_(Incident.tenant_id == tenant.id, Incident.threat_tier == "HOT")
        )
        hot_result = await db.execute(hot_stmt)
        hot_count = hot_result.scalar() or 0
        
        warm_stmt = select(func.count(Incident.id)).where(
            and_(Incident.tenant_id == tenant.id, Incident.threat_tier == "WARM")
        )
        warm_result = await db.execute(warm_stmt)
        warm_count = warm_result.scalar() or 0
        
        cold_stmt = select(func.count(Incident.id)).where(
            and_(Incident.tenant_id == tenant.id, Incident.threat_tier == "COLD")
        )
        cold_result = await db.execute(cold_stmt)
        cold_count = cold_result.scalar() or 0
        
        # Status distribution
        new_stmt = select(func.count(Incident.id)).where(
            and_(Incident.tenant_id == tenant.id, Incident.status == "NEW")
        )
        new_result = await db.execute(new_stmt)
        new_count = new_result.scalar() or 0
        
        investigating_stmt = select(func.count(Incident.id)).where(
            and_(Incident.tenant_id == tenant.id, Incident.status == "INVESTIGATING")
        )
        investigating_result = await db.execute(investigating_stmt)
        investigating_count = investigating_result.scalar() or 0
        
        resolved_stmt = select(func.count(Incident.id)).where(
            and_(Incident.tenant_id == tenant.id, Incident.status == "RESOLVED")
        )
        resolved_result = await db.execute(resolved_stmt)
        resolved_count = resolved_result.scalar() or 0
        
        # Detection rate (resolved / total)
        detection_rate = (resolved_count / total_alerts * 100) if total_alerts > 0 else 0
        
        # 24-hour trend
        now = datetime.utcnow()
        alerts_24h = []
        
        for hour in range(24):
            hour_start = now - timedelta(hours=24-hour)
            hour_end = hour_start + timedelta(hours=1)
            
            hour_stmt = select(func.count(Incident.id)).where(
                and_(
                    Incident.tenant_id == tenant.id,
                    Incident.detected_at >= hour_start,
                    Incident.detected_at < hour_end
                )
            )
            hour_result = await db.execute(hour_stmt)
            count = hour_result.scalar() or 0
            
            alerts_24h.append({
                "hour": hour_start.strftime("%H:00"),
                "count": count
            })
        
        # Threat distribution (simplified)
        threat_distribution = {
            "phishing": hot_count + warm_count,
            "malware": cold_count,
            "suspicious_url": warm_count
        }
        
        # Severity distribution
        severity_distribution = {
            "critical": hot_count,
            "high": warm_count,
            "medium": cold_count // 2 if cold_count > 0 else 0,
            "low": cold_count // 2 if cold_count > 0 else 0
        }
        
        return SOCMetricsResponse(
            total_alerts=total_alerts,
            hot_count=hot_count,
            warm_count=warm_count,
            cold_count=cold_count,
            new_count=new_count,
            investigating_count=investigating_count,
            resolved_count=resolved_count,
            detection_rate=round(detection_rate, 2),
            alerts_24h=alerts_24h,
            threat_distribution=threat_distribution,
            severity_distribution=severity_distribution
        )
        
    except Exception as e:
        logger.error(f"Error fetching SOC metrics: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error fetching metrics"
        )

@router.get("/{incident_id}", response_model=dict)
async def get_incident_details(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    tenant: Tenant = Depends(get_current_tenant)
):
    """Get detailed information about a specific incident"""
    try:
        stmt = select(Incident, ScanResult).join(
            ScanResult, Incident.scan_result_id == ScanResult.id
        ).where(
            and_(
                Incident.id == incident_id,
                Incident.tenant_id == tenant.id
            )
        )
        
        result = await db.execute(stmt)
        incident_scan = result.first()
        
        if not incident_scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Incident not found"
            )
        
        incident, scan = incident_scan
        
        return {
            "incident": {
                "id": incident.id,
                "title": incident.title,
                "severity": incident.severity,
                "status": incident.status,
                "threat_tier": incident.threat_tier,
                "assigned_to": incident.assigned_to,
                "notes": incident.notes,
                "resolution": incident.resolution,
                "detected_at": incident.detected_at.isoformat(),
                "investigated_at": incident.investigated_at.isoformat() if incident.investigated_at else None,
                "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
            },
            "scan_result": {
                "subject": scan.subject,
                "body": scan.body,
                "urls": scan.urls,
                "verdict": scan.verdict,
                "risk_score": scan.risk_score,
                "confidence": scan.confidence,
                "phishing_indicators": scan.phishing_indicators,
                "url_reputation": scan.url_reputation,
                "malware_detected": scan.malware_detected,
                "malware_details": scan.malware_details,
                "mitre_attack_tags": scan.mitre_attack_tags,
                "source": scan.source
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching incident details: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error fetching incident details"
        )

@router.patch("/{incident_id}")
async def update_incident(
    incident_id: int,
    update_data: UpdateIncidentRequest,
    db: AsyncSession = Depends(get_db),
    tenant: Tenant = Depends(get_current_tenant)
):
    """Update incident status, assignment, or notes"""
    try:
        stmt = select(Incident).where(
            and_(
                Incident.id == incident_id,
                Incident.tenant_id == tenant.id
            )
        )
        result = await db.execute(stmt)
        incident = result.scalar_one_or_none()
        
        if not incident:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Incident not found"
            )
        
        # Update fields
        if update_data.status:
            incident.status = update_data.status.upper()
            if update_data.status.upper() == "INVESTIGATING" and not incident.investigated_at:
                incident.investigated_at = datetime.utcnow()
            elif update_data.status.upper() == "RESOLVED" and not incident.resolved_at:
                incident.resolved_at = datetime.utcnow()
        
        if update_data.assigned_to:
            incident.assigned_to = update_data.assigned_to
        
        if update_data.notes:
            incident.notes = update_data.notes
        
        if update_data.resolution:
            incident.resolution = update_data.resolution
        
        incident.updated_at = datetime.utcnow()
        
        await db.commit()
        
        return {"message": "Incident updated successfully", "incident_id": incident.id}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating incident: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error updating incident"
        )