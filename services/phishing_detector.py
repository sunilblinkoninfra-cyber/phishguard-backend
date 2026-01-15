import re
import logging
from typing import Dict, List, Tuple
from urllib.parse import urlparse
import nltk
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# Download required NLTK data on first run
try:
    nltk.data.find('tokenizers/punkt')
except LookupError:
    nltk.download('punkt', quiet=True)

class PhishingDetector:
    """Advanced phishing detection engine"""
    
    # Suspicious keywords
    URGENCY_KEYWORDS = [
        'urgent', 'immediate', 'action required', 'suspended', 'locked',
        'verify', 'confirm', 'update', 'expire', 'limited time', 'act now',
        'click here', 'deadline', 'unauthorized', 'suspicious activity'
    ]
    
    FINANCIAL_KEYWORDS = [
        'bank', 'credit card', 'account', 'password', 'social security',
        'tax', 'refund', 'payment', 'invoice', 'wire transfer', 'paypal',
        'bitcoin', 'cryptocurrency', 'wallet'
    ]
    
    IMPERSONATION_KEYWORDS = [
        'microsoft', 'google', 'amazon', 'apple', 'facebook', 'netflix',
        'irs', 'fbi', 'dhl', 'fedex', 'ups', 'it department', 'admin',
        'support team', 'security team'
    ]
    
    # Suspicious TLDs
    SUSPICIOUS_TLDS = [
        '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club',
        '.work', '.click', '.link', '.bid', '.date', '.download'
    ]
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def analyze_email(self, subject: str, body: str, urls: List[str]) -> Dict:
        """
        Comprehensive email phishing analysis
        
        Returns:
            Dict with risk_score, indicators, and threat_tier
        """
        indicators = []
        risk_score = 0.0
        
        # Analyze subject
        subject_risk, subject_indicators = self._analyze_subject(subject)
        risk_score += subject_risk
        indicators.extend(subject_indicators)
        
        # Analyze body
        body_risk, body_indicators = self._analyze_body(body)
        risk_score += body_risk
        indicators.extend(body_indicators)
        
        # Analyze URLs
        url_risk, url_indicators = self._analyze_urls(urls)
        risk_score += url_risk
        indicators.extend(url_indicators)
        
        # Calculate confidence
        confidence = min(risk_score / 100.0, 1.0)
        
        # Determine threat tier
        threat_tier = self._calculate_threat_tier(risk_score)
        
        # Determine verdict
        if risk_score >= 70:
            verdict = "MALICIOUS"
        elif risk_score >= 40:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"
        
        return {
            "risk_score": round(risk_score, 2),
            "confidence": round(confidence, 2),
            "verdict": verdict,
            "threat_tier": threat_tier,
            "indicators": indicators,
            "mitre_attack_tags": self._map_to_mitre(indicators)
        }
    
    def _analyze_subject(self, subject: str) -> Tuple[float, List[Dict]]:
        """Analyze email subject for phishing indicators"""
        if not subject:
            return 0.0, []
        
        risk = 0.0
        indicators = []
        subject_lower = subject.lower()
        
        # Check for urgency
        urgency_found = [kw for kw in self.URGENCY_KEYWORDS if kw in subject_lower]
        if urgency_found:
            risk += 15.0
            indicators.append({
                "type": "urgency_language",
                "severity": "medium",
                "description": f"Urgency keywords detected: {', '.join(urgency_found)}",
                "value": urgency_found
            })
        
        # Check for excessive punctuation
        if subject.count('!') > 2 or subject.count('?') > 2:
            risk += 10.0
            indicators.append({
                "type": "excessive_punctuation",
                "severity": "low",
                "description": "Excessive use of exclamation or question marks",
                "value": f"!: {subject.count('!')}, ?: {subject.count('?')}"
            })
        
        # Check for all caps
        if subject.isupper() and len(subject) > 10:
            risk += 12.0
            indicators.append({
                "type": "all_caps_subject",
                "severity": "medium",
                "description": "Subject line is entirely in capital letters",
                "value": subject
            })
        
        # Check for RE:/FW: without context
        if re.match(r'^(re|fw|fwd):', subject_lower) and len(subject) < 20:
            risk += 8.0
            indicators.append({
                "type": "fake_reply",
                "severity": "low",
                "description": "Suspicious RE:/FW: prefix",
                "value": subject
            })
        
        return risk, indicators
    
    def _analyze_body(self, body: str) -> Tuple[float, List[Dict]]:
        """Analyze email body for phishing indicators"""
        if not body:
            return 0.0, []
        
        risk = 0.0
        indicators = []
        
        # Parse HTML if present
        soup = BeautifulSoup(body, 'html.parser')
        text = soup.get_text()
        text_lower = text.lower()
        
        # Check for financial keywords
        financial_found = [kw for kw in self.FINANCIAL_KEYWORDS if kw in text_lower]
        if financial_found:
            risk += 20.0
            indicators.append({
                "type": "financial_content",
                "severity": "high",
                "description": f"Financial keywords detected: {', '.join(financial_found[:5])}",
                "value": financial_found[:5]
            })
        
        # Check for credential requests
        if re.search(r'(password|username|ssn|social security)', text_lower):
            risk += 25.0
            indicators.append({
                "type": "credential_request",
                "severity": "critical",
                "description": "Email requests sensitive credentials",
                "value": "Credential request detected"
            })
        
        # Check for impersonation
        impersonation_found = [kw for kw in self.IMPERSONATION_KEYWORDS if kw in text_lower]
        if impersonation_found:
            risk += 18.0
            indicators.append({
                "type": "brand_impersonation",
                "severity": "high",
                "description": f"Potential brand impersonation: {', '.join(impersonation_found[:3])}",
                "value": impersonation_found[:3]
            })
        
        # Check for hidden links (different href and text)
        links = soup.find_all('a', href=True)
        for link in links:
            href = link.get('href', '')
            text = link.get_text().strip()
            if text and href and text != href and not href.startswith('#'):
                if urlparse(href).netloc and urlparse(text if text.startswith('http') else '').netloc:
                    if urlparse(href).netloc != urlparse(text).netloc:
                        risk += 15.0
                        indicators.append({
                            "type": "deceptive_link",
                            "severity": "high",
                            "description": "Link text doesn't match destination",
                            "value": {"text": text[:50], "href": href[:100]}
                        })
                        break
        
        # Check for generic greetings
        if re.search(r'^(dear (customer|user|member)|hello,|hi,)', text_lower.strip()):
            risk += 8.0
            indicators.append({
                "type": "generic_greeting",
                "severity": "low",
                "description": "Generic greeting instead of personalized",
                "value": "Generic greeting detected"
            })
        
        # Check for spelling/grammar issues (simplified)
        common_errors = ['recieve', 'occured', 'seperate', 'definately', 'alot']
        errors_found = [err for err in common_errors if err in text_lower]
        if errors_found:
            risk += 10.0
            indicators.append({
                "type": "spelling_errors",
                "severity": "medium",
                "description": "Common spelling errors detected",
                "value": errors_found
            })
        
        return risk, indicators
    
    def _analyze_urls(self, urls: List[str]) -> Tuple[float, List[Dict]]:
        """Analyze URLs for phishing indicators"""
        if not urls:
            return 0.0, []
        
        risk = 0.0
        indicators = []
        
        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                
                # Check suspicious TLDs
                tld = '.' + domain.split('.')[-1] if '.' in domain else ''
                if tld in self.SUSPICIOUS_TLDS:
                    risk += 12.0
                    indicators.append({
                        "type": "suspicious_tld",
                        "severity": "medium",
                        "description": f"Suspicious top-level domain: {tld}",
                        "value": url
                    })
                
                # Check for IP address instead of domain
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
                    risk += 20.0
                    indicators.append({
                        "type": "ip_address_url",
                        "severity": "high",
                        "description": "URL uses IP address instead of domain",
                        "value": url
                    })
                
                # Check for suspicious subdomains
                if domain.count('.') > 2:
                    risk += 10.0
                    indicators.append({
                        "type": "excessive_subdomains",
                        "severity": "medium",
                        "description": "Excessive number of subdomains",
                        "value": domain
                    })
                
                # Check for homograph attacks
                suspicious_chars = ['а', 'е', 'о', 'р', 'с', 'х']  # Cyrillic lookalikes
                if any(char in domain for char in suspicious_chars):
                    risk += 25.0
                    indicators.append({
                        "type": "homograph_attack",
                        "severity": "critical",
                        "description": "Domain contains lookalike characters",
                        "value": domain
                    })
                
                # Check URL length
                if len(url) > 150:
                    risk += 8.0
                    indicators.append({
                        "type": "long_url",
                        "severity": "low",
                        "description": "Unusually long URL",
                        "value": f"{len(url)} characters"
                    })
                
                # Check for @ symbol in URL
                if '@' in url:
                    risk += 15.0
                    indicators.append({
                        "type": "at_symbol_in_url",
                        "severity": "high",
                        "description": "@ symbol used to obfuscate destination",
                        "value": url
                    })
                
            except Exception as e:
                self.logger.warning(f"Error analyzing URL {url}: {e}")
        
        return risk, indicators
    
    def _calculate_threat_tier(self, risk_score: float) -> str:
        """Calculate threat tier based on risk score"""
        if risk_score >= 70:
            return "HOT"
        elif risk_score >= 40:
            return "WARM"
        else:
            return "COLD"
    
    def _map_to_mitre(self, indicators: List[Dict]) -> List[str]:
        """Map indicators to MITRE ATT&CK techniques"""
        tags = set()
        
        indicator_types = [ind['type'] for ind in indicators]
        
        if 'credential_request' in indicator_types:
            tags.add("T1566.002")  # Phishing: Spearphishing Link
            tags.add("T1589")      # Credential Access
        
        if 'deceptive_link' in indicator_types or 'homograph_attack' in indicator_types:
            tags.add("T1566.002")  # Phishing: Spearphishing Link
        
        if 'brand_impersonation' in indicator_types:
            tags.add("T1656")      # Impersonation
        
        if 'financial_content' in indicator_types:
            tags.add("T1534")      # Internal Spearphishing
        
        return list(tags)