import re
import json
from datetime import datetime

class PatternDetector:
    def __init__(self):
        # Enhanced fraud patterns with more keywords and context
        self.fraud_patterns = {
            'account_takeover': {
                'keywords': ['credential stuffing', 'session hijacking', 'sim swap', 'account takeover', 'ATO', 'password spray', 'MFA bypass', 'session cookie', 'token theft'],
                'clari5_scenario': '5.1.1',
                'risk_level': 'High',
                'description': 'Unauthorized account access leading to fraudulent transactions'
            },
            'social_engineering': {
                'keywords': ['phishing', 'vishing', 'business email compromise', 'BEC', 'impersonation', 'social engineering', 'CEO fraud', 'invoice fraud', 'romance scam'],
                'clari5_scenario': '5.1.17',
                'risk_level': 'High',
                'description': 'Manipulation techniques to trick victims into authorizing transactions'
            },
            'malware_fraud': {
                'keywords': ['banking trojan', 'keylogger', 'ransomware', 'malware', 'botnet', 'info stealer', 'remote access trojan', 'RAT', 'spyware', 'formgrabber'],
                'clari5_scenario': '5.1.12',
                'risk_level': 'High',
                'description': 'Malicious software designed to steal financial credentials or data'
            },
            'insider_threat': {
                'keywords': ['insider threat', 'privilege abuse', 'data exfiltration', 'employee fraud', 'internal threat', 'rogue employee', 'privilege escalation'],
                'clari5_scenario': '5.1.5',
                'risk_level': 'Medium',
                'description': 'Fraudulent activities conducted by authorized internal users'
            },
            'money_laundering': {
                'keywords': ['money laundering', 'structuring', 'smurfing', 'mule account', 'layering', 'placement', 'integration', 'suspicious transaction'],
                'clari5_scenario': '4.4.13',
                'risk_level': 'High',
                'description': 'Methods to conceal the origin of illegally obtained funds'
            },
            'api_abuse': {
                'keywords': ['API abuse', 'credential stuffing', 'rate limiting', 'API security', 'endpoint abuse', 'API scraping', 'automated attack'],
                'clari5_scenario': '5.1.12',
                'risk_level': 'Medium',
                'description': 'Exploitation of banking APIs for fraudulent activities'
            },
            'synthetic_fraud': {
                'keywords': ['synthetic identity', 'fake identity', 'fabricated identity', 'identity fraud', 'new account fraud'],
                'clari5_scenario': '5.1.17',
                'risk_level': 'High',
                'description': 'Creation of fake identities to open fraudulent accounts'
            },
            'authorized_push_payment': {
                'keywords': ['authorized push payment', 'APP fraud', 'authorized fraud', 'real-time fraud', 'instant payment fraud'],
                'clari5_scenario': '5.1.1',
                'risk_level': 'High',
                'description': 'Victims are tricked into authorizing fraudulent payments'
            }
        }
        
        # Financial institution keywords for context
        self.financial_keywords = ['bank', 'payment', 'financial', 'transaction', 'card', 'transfer', 'account', 'fund', 'wire', 'ACH', 'POS', 'ATM']
    
    def detect_patterns(self, text):
        """Enhanced pattern detection with context analysis"""
        if not text:
            return []
        
        text_lower = text.lower()
        detected_patterns = []
        
        for pattern_name, pattern_info in self.fraud_patterns.items():
            matches = []
            
            # Check for pattern keywords
            for keyword in pattern_info['keywords']:
                if keyword in text_lower:
                    matches.append({
                        'keyword': keyword,
                        'context': self._get_context(text_lower, keyword),
                        'position': text_lower.find(keyword)
                    })
            
            if matches:
                # Calculate confidence based on multiple factors
                confidence = self._calculate_confidence(text_lower, matches, pattern_name)
                
                detected_patterns.append({
                    'pattern': pattern_name,
                    'matches': matches,
                    'clari5_scenario': pattern_info['clari5_scenario'],
                    'risk_level': pattern_info['risk_level'],
                    'description': pattern_info['description'],
                    'confidence': confidence,
                    'financial_context': self._has_financial_context(text_lower)
                })
        
        return detected_patterns
    
    def _get_context(self, text, keyword, window=50):
        """Extract context around the keyword"""
        start = max(0, text.find(keyword) - window)
        end = min(len(text), text.find(keyword) + len(keyword) + window)
        return text[start:end].strip()
    
    def _has_financial_context(self, text):
        """Check if text has financial context"""
        return any(keyword in text for keyword in self.financial_keywords)
    
    def _calculate_confidence(self, text, matches, pattern_name):
        """Calculate confidence score with multiple factors"""
        confidence = 0.3  # Base confidence
        
        # Factor 1: Number of keyword matches
        confidence += min(len(matches) * 0.2, 0.4)
        
        # Factor 2: Financial context
        if self._has_financial_context(text):
            confidence += 0.2
        
        # Factor 3: Specific high-confidence terms
        high_confidence_terms = {
            'zero-day': 0.3,
            'exploit': 0.2,
            'active attack': 0.25,
            'campaign': 0.15,
            'breach': 0.2,
            'data leak': 0.15
        }
        
        for term, boost in high_confidence_terms.items():
            if term in text:
                confidence += boost
        
        # Factor 4: Pattern-specific boosts
        pattern_boosts = {
            'malware_fraud': 0.1,  # Very specific to fraud
            'account_takeover': 0.1,
            'money_laundering': 0.15  # Very specific to banking
        }
        
        confidence += pattern_boosts.get(pattern_name, 0)
        
        return min(confidence, 1.0)
    
    def extract_iocs(self, text):
        """Enhanced IOC extraction"""
        iocs = {
            'ips': list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text))),
            'domains': list(set(re.findall(r'\b[a-zA-Z0-9]+[.][a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?\b', text))),
            'hashes': list(set(re.findall(r'\b[a-fA-F0-9]{32,128}\b', text))),
            'cves': list(set(re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE))),
            'emails': list(set(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text))),
            'urls': list(set(re.findall(r'https?://[^\s]+', text)))
        }
        
        # Filter out common false positives
        iocs['domains'] = [d for d in iocs['domains'] if not any(common in d for common in ['example.com', 'test.com'])]
        iocs['emails'] = [e for e in iocs['emails'] if not any(common in e for common in ['example.com', 'test.com'])]
        
        return iocs
    
    def generate_clari5_scenario(self, pattern_detection, original_article):
        """Generate enhanced Clari5 scenario proposal"""
        # Scenario parameters based on pattern type
        scenario_parameters = {
            'account_takeover': {'X': '20000', 'D': '30 minutes'},
            'social_engineering': {'X': '50000', 'D': '1 day'},
            'malware_fraud': {'X-CNP': '10000', 'X-ecom': '15000'},
            'money_laundering': {'X1': '10000', 'X2': '100000', 'N': '3', 'D': '1 day'},
            'api_abuse': {'X': '15000', 'D': '1 hour'},
            'default': {'X': '25000', 'D': '1 day'}
        }
        
        params = scenario_parameters.get(pattern_detection['pattern'], scenario_parameters['default'])
        
        scenario = {
            "scenario_type": pattern_detection['clari5_scenario'],
            "title": f"Auto-detected: {pattern_detection['pattern'].replace('_', ' ').title()}",
            "description": pattern_detection['description'],
            "risk_level": pattern_detection['risk_level'],
            "confidence_score": round(pattern_detection['confidence'], 2),
            "source_reference": {
                "url": original_article.get('url', ''),
                "title": original_article.get('title', ''),
                "source": original_article.get('source', ''),
                "published": original_article.get('published', '')
            },
            "detected_pattern": pattern_detection['pattern'],
            "keyword_matches": [match['keyword'] for match in pattern_detection['matches']],
            "configurable_parameters": params,
            "iocs": self.extract_iocs(original_article.get('content', '') + original_article.get('title', '')),
            "financial_context_detected": pattern_detection['financial_context'],
            "generated_timestamp": datetime.now().isoformat(),
            "recommended_actions": [
                "Review and tune scenario parameters in Clari5",
                "Verify IOCs with internal threat intelligence",
                "Monitor transaction patterns matching this threat",
                "Update customer risk scores if applicable",
                "Share findings with security team"
            ]
        }
        
        return scenario