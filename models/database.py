from datetime import datetime
from enum import Enum
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, JSON, Float, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class ThreatTier(str, Enum):
    HOT = "HOT"
    WARM = "WARM"
    COLD = "COLD"

class IncidentStatus(str, Enum):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"

class PlanTier(str, Enum):
    FREE = "FREE"
    PRO = "PRO"
    ENTERPRISE = "ENTERPRISE"

class Tenant(Base):
    """Multi-tenant organization model"""
    __tablename__ = "tenants"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    email = Column(String(255), unique=True, nullable=False, index=True)
    plan_tier = Column(String(20), default=PlanTier.FREE.value)
    api_key = Column(String(64), unique=True, nullable=False, index=True)
    is_active = Column(Boolean, default=True)
    api_calls_used = Column(Integer, default=0)
    api_calls_limit = Column(Integer, default=100)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    incidents = relationship("Incident", back_populates="tenant", cascade="all, delete-orphan")
    scans = relationship("ScanResult", back_populates="tenant", cascade="all, delete-orphan")

class ScanResult(Base):
    """Scan results for emails/URLs/files"""
    __tablename__ = "scan_results"
    
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    
    # Scan input
    scan_type = Column(String(50))  # email, url, file
    subject = Column(String(500))
    body = Column(Text)
    urls = Column(JSON)
    attachments = Column(JSON)
    source = Column(String(100))  # API, O365, Gmail, SMTP
    
    # Results
    verdict = Column(String(50))  # MALICIOUS, SUSPICIOUS, CLEAN
    threat_tier = Column(String(10))  # HOT, WARM, COLD
    risk_score = Column(Float)
    confidence = Column(Float)
    
    # Detection details
    phishing_indicators = Column(JSON)
    malware_detected = Column(Boolean, default=False)
    malware_details = Column(JSON)
    url_reputation = Column(JSON)
    mitre_attack_tags = Column(JSON)
    
    # Metadata
    scan_duration_ms = Column(Integer)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    tenant = relationship("Tenant", back_populates="scans")
    incident = relationship("Incident", back_populates="scan_result", uselist=False)

class Incident(Base):
    """Security incidents"""
    __tablename__ = "incidents"
    
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    scan_result_id = Column(Integer, ForeignKey("scan_results.id"), unique=True)
    
    # Incident details
    title = Column(String(500))
    severity = Column(String(20))  # CRITICAL, HIGH, MEDIUM, LOW
    status = Column(String(50), default=IncidentStatus.NEW.value, index=True)
    threat_tier = Column(String(10))
    
    # Investigation
    assigned_to = Column(String(255))
    notes = Column(Text)
    resolution = Column(Text)
    
    # Timestamps
    detected_at = Column(DateTime, default=datetime.utcnow)
    investigated_at = Column(DateTime)
    resolved_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    tenant = relationship("Tenant", back_populates="incidents")
    scan_result = relationship("ScanResult", back_populates="incident")

class URLReputation(Base):
    """Cache for URL reputation checks"""
    __tablename__ = "url_reputation"
    
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(2048), unique=True, index=True)
    is_malicious = Column(Boolean)
    reputation_score = Column(Float)
    sources = Column(JSON)  # VirusTotal, URLhaus, PhishTank
    last_checked = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)

class AuditLog(Base):
    """Audit trail for compliance"""
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"))
    action = Column(String(100))
    resource_type = Column(String(50))
    resource_id = Column(Integer)
    user_email = Column(String(255))
    ip_address = Column(String(45))
    user_agent = Column(Text)
    details = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)