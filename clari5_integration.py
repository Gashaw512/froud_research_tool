import requests
import json
from datetime import datetime

class UnifiedClari5Integration:
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f"Bearer {config['auth_token']}",
            'Content-Type': 'application/json'
        })
    
    def create_fraud_alert(self, detection_data):
        """Create fraud detection alert in Clari5"""
        alert_payload = {
            "project_id": self.config['fraud_project_id'],
            "alert_type": "FRAUD_PATTERN",
            "detection_data": detection_data,
            "timestamp": datetime.now().isoformat(),
            "priority": self.calculate_priority(detection_data)
        }
        
        return self._send_to_clari5('/api/alerts/fraud', alert_payload)
    
    def create_sanction_alert(self, screening_data):
        """Create sanction screening alert in Clari5"""
        alert_payload = {
            "project_id": self.config['sanction_project_id'],
            "alert_type": "SANCTION_MATCH",
            "screening_data": screening_data,
            "timestamp": datetime.now().isoformat(),
            "priority": "HIGH" if screening_data['match_score'] > 0.8 else "MEDIUM"
        }
        
        return self._send_to_clari5('/api/alerts/sanction', alert_payload)
    
    def create_correlation_alert(self, correlation_data):
        """Create cyber-fraud correlation alert in Clari5"""
        alert_payload = {
            "project_id": self.config['correlation_project_id'],
            "alert_type": "CYBER_FRAUD_CORRELATION",
            "correlation_data": correlation_data,
            "timestamp": datetime.now().isoformat(),
            "priority": "HIGH"
        }
        
        return self._send_to_clari5('/api/alerts/correlation', alert_payload)
    
    def _send_to_clari5(self, endpoint, payload):
        """Generic method to send alerts to Clari5"""
        try:
            response = self.session.post(
                f"{self.config['base_url']}{endpoint}",
                json=payload,
                timeout=30
            )
            
            if response.status_code in [200, 201]:
                alert_id = response.json().get('alert_id')
                print(f"✅ Clari5 alert created: {alert_id}")
                return alert_id
            else:
                print(f"❌ Clari5 API error: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            print(f"❌ Clari5 connection error: {e}")
            return None
    
    def calculate_priority(self, detection_data):
        """Calculate alert priority based on risk factors"""
        risk_score = detection_data.get('confidence_score', 0)
        
        if risk_score >= 0.8:
            return "HIGH"
        elif risk_score >= 0.6:
            return "MEDIUM"
        else:
            return "LOW"