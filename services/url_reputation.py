import logging
import hashlib
from typing import List, Dict
from datetime import datetime, timedelta
import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models.database import URLReputation
from core.config import settings

logger = logging.getLogger(__name__)

class URLReputationService:
    """Service for checking URL reputation across multiple threat intelligence sources"""
    
    def __init__(self):
        self.cache_duration = timedelta(hours=24)
        self.timeout = 10  # seconds
    
    async def check_urls(self, urls: List[str], db: AsyncSession) -> Dict[str, Dict]:
        """
        Check reputation of multiple URLs
        
        Returns dict mapping URL to reputation data
        """
        results = {}
        
        for url in urls:
            try:
                # Check cache first
                cached = await self._get_cached_reputation(url, db)
                if cached:
                    results[url] = cached
                else:
                    # Perform live checks
                    reputation = await self._check_url_live(url)
                    
                    # Cache result
                    await self._cache_reputation(url, reputation, db)
                    results[url] = reputation
                    
            except Exception as e:
                logger.error(f"Error checking URL {url}: {e}")
                results[url] = {
                    "is_malicious": False,
                    "reputation_score": 50,
                    "sources": {},
                    "error": str(e)
                }
        
        return results
    
    async def _get_cached_reputation(self, url: str, db: AsyncSession) -> Dict:
        """Get cached URL reputation if available and fresh"""
        stmt = select(URLReputation).where(URLReputation.url == url)
        result = await db.execute(stmt)
        cached = result.scalar_one_or_none()
        
        if cached:
            age = datetime.utcnow() - cached.last_checked
            if age < self.cache_duration:
                return {
                    "is_malicious": cached.is_malicious,
                    "reputation_score": cached.reputation_score,
                    "sources": cached.sources,
                    "cached": True,
                    "last_checked": cached.last_checked.isoformat()
                }
        
        return None
    
    async def _check_url_live(self, url: str) -> Dict:
        """Perform live URL reputation checks"""
        sources = {}
        is_malicious = False
        reputation_score = 50  # Neutral
        
        # Check URLhaus
        try:
            urlhaus_result = await self._check_urlhaus(url)
            sources["urlhaus"] = urlhaus_result
            if urlhaus_result.get("threat") in ["malware", "malware_download"]:
                is_malicious = True
                reputation_score = min(reputation_score - 30, 0)
        except Exception as e:
            logger.warning(f"URLhaus check failed: {e}")
            sources["urlhaus"] = {"error": str(e)}
        
        # Check VirusTotal (if API key available)
        if settings.VIRUSTOTAL_API_KEY:
            try:
                vt_result = await self._check_virustotal(url)
                sources["virustotal"] = vt_result
                
                if vt_result.get("malicious", 0) > 2:
                    is_malicious = True
                    reputation_score = min(reputation_score - 40, 0)
                elif vt_result.get("suspicious", 0) > 0:
                    reputation_score -= 20
            except Exception as e:
                logger.warning(f"VirusTotal check failed: {e}")
                sources["virustotal"] = {"error": str(e)}
        
        # Simple heuristics
        heuristic_score = self._heuristic_check(url)
        sources["heuristics"] = {"score": heuristic_score}
        reputation_score += heuristic_score
        
        # Normalize reputation score (0-100, lower is worse)
        reputation_score = max(0, min(100, reputation_score))
        
        return {
            "is_malicious": is_malicious,
            "reputation_score": reputation_score,
            "sources": sources,
            "cached": False,
            "last_checked": datetime.utcnow().isoformat()
        }
    
    async def _check_urlhaus(self, url: str) -> Dict:
        """Check URL against URLhaus database"""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{settings.URLHAUS_API_URL}url/",
                data={"url": url}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("query_status") == "ok":
                    return {
                        "found": True,
                        "threat": data.get("threat"),
                        "tags": data.get("tags", []),
                        "first_seen": data.get("date_added")
                    }
            
            return {"found": False}
    
    async def _check_virustotal(self, url: str) -> Dict:
        """Check URL against VirusTotal"""
        url_id = hashlib.sha256(url.encode()).hexdigest()
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
            
            response = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "total_engines": sum(stats.values())
                }
            
            return {"error": "Not found or rate limited"}
    
    def _heuristic_check(self, url: str) -> int:
        """Simple heuristic checks for URL safety"""
        score = 0
        url_lower = url.lower()
        
        # Suspicious keywords in URL
        suspicious_keywords = ['login', 'verify', 'account', 'secure', 'update', 'confirm']
        if any(kw in url_lower for kw in suspicious_keywords):
            score -= 10
        
        # Very long URLs
        if len(url) > 150:
            score -= 5
        
        # IP address in URL
        import re
        if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            score -= 15
        
        # Suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
        if any(url_lower.endswith(tld) for tld in suspicious_tlds):
            score -= 15
        
        # HTTPS is good
        if url_lower.startswith('https://'):
            score += 5
        
        return score
    
    async def _cache_reputation(self, url: str, reputation: Dict, db: AsyncSession):
        """Cache URL reputation result"""
        try:
            # Check if exists
            stmt = select(URLReputation).where(URLReputation.url == url)
            result = await db.execute(stmt)
            existing = result.scalar_one_or_none()
            
            if existing:
                existing.is_malicious = reputation["is_malicious"]
                existing.reputation_score = reputation["reputation_score"]
                existing.sources = reputation["sources"]
                existing.last_checked = datetime.utcnow()
            else:
                new_rep = URLReputation(
                    url=url,
                    is_malicious=reputation["is_malicious"],
                    reputation_score=reputation["reputation_score"],
                    sources=reputation["sources"]
                )
                db.add(new_rep)
            
            await db.commit()
        except Exception as e:
            logger.error(f"Error caching reputation: {e}")
            await db.rollback()