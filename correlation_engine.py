"""
Cyber-Fraud Correlation Engine
Correlates cyber threat intelligence with financial fraud patterns
"""

import sqlite3
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import re

class CyberFraudCorrelationEngine:
    """Advanced engine for correlating cyber threats with fraud patterns"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.db_conn = sqlite3.connect(db_path)
        self._setup_correlation_tables()
    
    def _setup_correlation_tables(self) -> None:
        """Initialize correlation database tables"""
        cursor = self.db_conn.cursor()
        
        # Cyber threat events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cyber_threat_events (
                id INTEGER PRIMARY KEY,
                event_type TEXT,
                customer_id TEXT,
                event_data TEXT,
                severity TEXT,
                detected_at DATETIME,
                source TEXT,
                iocs TEXT
            )
        ''')
        
        # Fraud events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS fraud_events (
                id INTEGER PRIMARY KEY,
                event_type TEXT,
                customer_id TEXT,
                transaction_data TEXT,
                amount REAL,
                risk_score REAL,
                detected_at DATETIME,
                status TEXT
            )
        ''')
        
        # Correlation results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS correlation_results (
                id INTEGER PRIMARY KEY,
                cyber_event_id INTEGER,
                fraud_event_id INTEGER,
                correlation_type TEXT,
                confidence_score REAL,
                correlation_factors TEXT,
                created_at DATETIME,
                status TEXT,
                FOREIGN KEY (cyber_event_id) REFERENCES cyber_threat_events (id),
                FOREIGN KEY (fraud_event_id) REFERENCES fraud_events (id)
            )
        ''')
        
        # Customer risk profiles
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS customer_risk_profiles (
                customer_id TEXT PRIMARY KEY,
                cyber_risk_score REAL DEFAULT 0,
                fraud_risk_score REAL DEFAULT 0,
                composite_risk_score REAL DEFAULT 0,
                last_updated DATETIME,
                risk_factors TEXT
            )
        ''')
        
        self.db_conn.commit()
    
    def analyze_recent_activity(self) -> List[Dict[str, Any]]:
        """
        Analyze recent activity for cyber-fraud correlations
        
        Returns:
            List of correlation findings
        """
        print("🔍 Analyzing recent activity for cyber-fraud correlations...")
        
        correlations = []
        
        # Get recent cyber events (last 7 days)
        recent_cyber_events = self._get_recent_cyber_events()
        
        # Get recent fraud events (last 7 days)
        recent_fraud_events = self._get_recent_fraud_events()
        
        # Look for temporal correlations
        temporal_correlations = self._find_temporal_correlations(
            recent_cyber_events, recent_fraud_events
        )
        correlations.extend(temporal_correlations)
        
        # Look for behavioral correlations
        behavioral_correlations = self._find_behavioral_correlations(
            recent_cyber_events, recent_fraud_events
        )
        correlations.extend(behavioral_correlations)
        
        # Look for IOC-based correlations
        ioc_correlations = self._find_ioc_correlations(
            recent_cyber_events, recent_fraud_events
        )
        correlations.extend(ioc_correlations)
        
        # Store correlations in database
        for correlation in correlations:
            self._store_correlation(correlation)
        
        print(f"✅ Found {len(correlations)} cyber-fraud correlations")
        return correlations
    
    def _get_recent_cyber_events(self, days: int = 7) -> List[Dict[str, Any]]:
        """Get recent cyber threat events"""
        cursor = self.db_conn.cursor()
        cutoff_date = datetime.now() - timedelta(days=days)
        
        cursor.execute('''
            SELECT * FROM cyber_threat_events 
            WHERE detected_at > ?
            ORDER BY detected_at DESC
        ''', (cutoff_date.isoformat(),))
        
        return [dict(row) for row in cursor.fetchall()]
    
    def _get_recent_fraud_events(self, days: int = 7) -> List[Dict[str, Any]]:
        """Get recent fraud events"""
        cursor = self.db_conn.cursor()
        cutoff_date = datetime.now() - timedelta(days=days)
        
        cursor.execute('''
            SELECT * FROM fraud_events 
            WHERE detected_at > ?
            ORDER BY detected_at DESC
        ''', (cutoff_date.isoformat(),))
        
        return [dict(row) for row in cursor.fetchall()]
    
    def _find_temporal_correlations(self, cyber_events: List[Dict], 
                                  fraud_events: List[Dict]) -> List[Dict[str, Any]]:
        """Find correlations based on timing between events"""
        correlations = []
        
        for cyber_event in cyber_events:
            cyber_time = datetime.fromisoformat(cyber_event['detected_at'])
            
            for fraud_event in fraud_events:
                if cyber_event['customer_id'] != fraud_event['customer_id']:
                    continue
                
                fraud_time = datetime.fromisoformat(fraud_event['detected_at'])
                time_diff = abs((fraud_time - cyber_time).total_seconds() / 3600)  # Hours
                
                # If fraud occurred within 24 hours of cyber event
                if time_diff <= 24:
                    confidence = max(0.8 - (time_diff / 48), 0.3)  # Higher confidence for closer events
                    
                    correlation = {
                        'correlation_type': 'TEMPORAL',
                        'cyber_event': cyber_event,
                        'fraud_event': fraud_event,
                        'confidence_score': round(confidence, 2),
                        'time_difference_hours': round(time_diff, 2),
                        'customer_id': cyber_event['customer_id'],
                        'risk_factors': [
                            f"Fraud event occurred {time_diff:.1f} hours after cyber event",
                            f"Cyber event type: {cyber_event['event_type']}",
                            f"Fraud event type: {fraud_event['event_type']}"
                        ],
                        'recommendation': 'Review customer transactions during this period'
                    }
                    
                    correlations.append(correlation)
        
        return correlations
    
    def _find_behavioral_correlations(self, cyber_events: List[Dict], 
                                    fraud_events: List[Dict]) -> List[Dict[str, Any]]:
        """Find correlations based on behavioral patterns"""
        correlations = []
        
        # Group events by customer
        customer_cyber_events = {}
        for event in cyber_events:
            customer_id = event['customer_id']
            if customer_id not in customer_cyber_events:
                customer_cyber_events[customer_id] = []
            customer_cyber_events[customer_id].append(event)
        
        customer_fraud_events = {}
        for event in fraud_events:
            customer_id = event['customer_id']
            if customer_id not in customer_fraud_events:
                customer_fraud_events[customer_id] = []
            customer_fraud_events[customer_id].append(event)
        
        # Analyze patterns for each customer
        for customer_id in set(customer_cyber_events.keys()) | set(customer_fraud_events.keys()):
            cyber_count = len(customer_cyber_events.get(customer_id, []))
            fraud_count = len(customer_fraud_events.get(customer_id, []))
            
            # If customer has both cyber and fraud events
            if cyber_count > 0 and fraud_count > 0:
                confidence = min(0.3 + (cyber_count * fraud_count * 0.1), 0.9)
                
                correlation = {
                    'correlation_type': 'BEHAVIORAL',
                    'customer_id': customer_id,
                    'cyber_event_count': cyber_count,
                    'fraud_event_count': fraud_count,
                    'confidence_score': round(confidence, 2),
                    'risk_factors': [
                        f"Multiple cyber events ({cyber_count}) and fraud events ({fraud_count})",
                        "Pattern suggests potential account compromise",
                        "Customer exhibits high-risk behavior across domains"
                    ],
                    'recommendation': 'Conduct comprehensive customer risk review'
                }
                
                correlations.append(correlation)
        
        return correlations
    
    def _find_ioc_correlations(self, cyber_events: List[Dict], 
                              fraud_events: List[Dict]) -> List[Dict[str, Any]]:
        """Find correlations based on shared Indicators of Compromise"""
        correlations = []
        
        for cyber_event in cyber_events:
            cyber_iocs = self._extract_iocs_from_event(cyber_event)
            
            for fraud_event in fraud_events:
                fraud_iocs = self._extract_iocs_from_event(fraud_event)
                
                # Find common IOCs
                common_iocs = set(cyber_iocs) & set(fraud_iocs)
                
                if common_iocs:
                    confidence = min(0.5 + (len(common_iocs) * 0.2), 0.9)
                    
                    correlation = {
                        'correlation_type': 'IOC_BASED',
                        'cyber_event': cyber_event,
                        'fraud_event': fraud_event,
                        'confidence_score': round(confidence, 2),
                        'shared_iocs': list(common_iocs),
                        'customer_id': cyber_event.get('customer_id', 'Unknown'),
                        'risk_factors': [
                            f"Shared IOCs: {len(common_iocs)} common indicators",
                            f"Cyber event: {cyber_event['event_type']}",
                            f"Fraud event: {fraud_event['event_type']}"
                        ],
                        'recommendation': 'Investigate shared IOCs for campaign identification'
                    }
                    
                    correlations.append(correlation)
        
        return correlations
    
    def _extract_iocs_from_event(self, event: Dict[str, Any]) -> List[str]:
        """Extract IOCs from event data"""
        iocs = []
        
        # Extract from event_data field
        event_data = event.get('event_data', '')
        if isinstance(event_data, str):
            # IP addresses
            iocs.extend(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', event_data))
            # Domains
            iocs.extend(re.findall(r'[a-zA-Z0-9]+[.][a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?', event_data))
            # Hashes
            iocs.extend(re.findall(r'\b[a-fA-F0-9]{32,128}\b', event_data))
        
        # Extract from dedicated IOCs field
        iocs_field = event.get('iocs', '')
        if iocs_field:
            try:
                if isinstance(iocs_field, str):
                    additional_iocs = json.loads(iocs_field)
                    iocs.extend(additional_iocs)
            except:
                pass
        
        return list(set(iocs))  # Remove duplicates
    
    def _store_correlation(self, correlation: Dict[str, Any]) -> None:
        """Store correlation result in database"""
        cursor = self.db_conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO correlation_results 
                (correlation_type, confidence_score, correlation_factors, created_at, status)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                correlation['correlation_type'],
                correlation['confidence_score'],
                json.dumps(correlation.get('risk_factors', [])),
                datetime.now().isoformat(),
                'NEW'
            ))
            
            self.db_conn.commit()
        except Exception as e:
            print(f"❌ Failed to store correlation: {e}")
    
    def assess_customer_cyber_risk(self, customer_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assess cyber risk for a customer
        
        Args:
            customer_data: Customer information
            
        Returns:
            Cyber risk assessment
        """
        customer_id = customer_data.get('customer_id')
        
        if not customer_id:
            return {'error': 'Customer ID required'}
        
        cursor = self.db_conn.cursor()
        
        # Get recent cyber events for customer
        cursor.execute('''
            SELECT COUNT(*) as event_count, 
                   AVG(CASE WHEN severity = 'HIGH' THEN 1.0 ELSE 0.5 END) as severity_score
            FROM cyber_threat_events 
            WHERE customer_id = ? AND detected_at > date('now', '-30 days')
        ''', (customer_id,))
        
        result = cursor.fetchone()
        event_count = result[0] if result else 0
        severity_score = result[1] if result and result[1] else 0
        
        # Calculate risk score (0-100)
        risk_score = min(event_count * 10 + severity_score * 50, 100)
        
        risk_level = 'LOW'
        if risk_score >= 70:
            risk_level = 'HIGH'
        elif risk_score >= 40:
            risk_level = 'MEDIUM'
        
        return {
            'customer_id': customer_id,
            'cyber_risk_score': round(risk_score, 2),
            'risk_level': risk_level,
            'recent_events_count': event_count,
            'factors': [
                f"Recent cyber events: {event_count}",
                f"Average severity: {severity_score:.2f}"
            ],
            'assessment_date': datetime.now().isoformat()
        }
    
    def get_customer_correlation_history(self, customer_id: str) -> List[Dict[str, Any]]:
        """Get correlation history for a specific customer"""
        cursor = self.db_conn.cursor()
        
        cursor.execute('''
            SELECT * FROM correlation_results cr
            LEFT JOIN cyber_threat_events ce ON cr.cyber_event_id = ce.id
            LEFT JOIN fraud_events fe ON cr.fraud_event_id = fe.id
            WHERE ce.customer_id = ? OR fe.customer_id = ?
            ORDER BY cr.created_at DESC
            LIMIT 20
        ''', (customer_id, customer_id))
        
        return [dict(row) for row in cursor.fetchall()]
    
    def generate_correlation_report(self, days: int = 30) -> Dict[str, Any]:
        """Generate comprehensive correlation report"""
        cursor = self.db_conn.cursor()
        
        # Get correlation statistics
        cursor.execute('''
            SELECT correlation_type, COUNT(*), AVG(confidence_score)
            FROM correlation_results 
            WHERE created_at > date('now', ?)
            GROUP BY correlation_type
        ''', (f'-{days} days',))
        
        stats = cursor.fetchall()
        
        # Get high-confidence correlations
        cursor.execute('''
            SELECT * FROM correlation_results 
            WHERE confidence_score >= 0.7 AND created_at > date('now', ?)
            ORDER BY confidence_score DESC
            LIMIT 10
        ''', (f'-{days} days',))
        
        high_risk_correlations = [dict(row) for row in cursor.fetchall()]
        
        return {
            'report_period_days': days,
            'generated_at': datetime.now().isoformat(),
            'correlation_statistics': [
                {
                    'type': row[0],
                    'count': row[1],
                    'avg_confidence': round(row[2], 2)
                } for row in stats
            ],
            'high_risk_correlations': high_risk_correlations,
            'total_correlations': sum(row[1] for row in stats),
            'high_confidence_count': len(high_risk_correlations)
        }

# Utility function to create sample data for testing
def create_sample_correlation_data(db_path: str) -> None:
    """Create sample data for testing correlation engine"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Sample cyber events
    sample_cyber_events = [
        ('PHISHING_ATTEMPT', 'CUST001', '{"ip": "192.168.1.100", "url": "phishy.com"}', 
         'HIGH', datetime.now().isoformat(), 'ThreatIntel', '["192.168.1.100", "phishy.com"]'),
        ('MALWARE_DETECTION', 'CUST002', '{"hash": "abc123def456", "type": "trojan"}', 
         'HIGH', (datetime.now() - timedelta(hours=2)).isoformat(), 'AVSystem', '["abc123def456"]'),
        ('ACCOUNT_TAKEOVER', 'CUST001', '{"method": "credential_stuffing", "success": true}', 
         'CRITICAL', (datetime.now() - timedelta(hours=1)).isoformat(), 'AuthSystem', '[]')
    ]
    
    cursor.executemany('''
        INSERT INTO cyber_threat_events 
        (event_type, customer_id, event_data, severity, detected_at, source, iocs)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', sample_cyber_events)
    
    # Sample fraud events
    sample_fraud_events = [
        ('UNAUTHORIZED_TRANSFER', 'CUST001', '{"amount": 5000, "recipient": "unknown"}', 
         5000.0, 0.95, datetime.now().isoformat(), 'OPEN'),
        ('ACCOUNT_TAKEOVER', 'CUST002', '{"method": "social_engineering"}', 
         0.0, 0.88, (datetime.now() - timedelta(hours=3)).isoformat(), 'INVESTIGATING'),
        ('MONEY_LAUNDERING', 'CUST001', '{"pattern": "structuring", "total": 15000}', 
         15000.0, 0.92, (datetime.now() - timedelta(hours=6)).isoformat(), 'OPEN')
    ]
    
    cursor.executemany('''
        INSERT INTO fraud_events 
        (event_type, customer_id, transaction_data, amount, risk_score, detected_at, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', sample_fraud_events)
    
    conn.commit()
    conn.close()
    print("✅ Sample correlation data created")

if __name__ == "__main__":
    # Test the correlation engine
    engine = CyberFraudCorrelationEngine('test_correlation.db')
    create_sample_correlation_data('test_correlation.db')
    
    results = engine.analyze_recent_activity()
    print(f"Found {len(results)} correlations")
    
    report = engine.generate_correlation_report(7)
    print(f"Report generated: {report['total_correlations']} total correlations")