#!/usr/bin/env python3
"""
Cyber-Fraud Intelligence Platform - Main Orchestrator
Integrates threat intelligence, fraud detection, sanction screening, and correlation analysis
"""

import json
import schedule
import time
import sqlite3
from datetime import datetime
from typing import Dict, List, Any, Optional

# Import platform components
from core_scraper import FraudPatternScraper
from pattern_detector import PatternDetector
from alert_manager import UnifiedAlertManager
from sanction_screener import IntegratedSanctionScreener
from correlation_engine import CyberFraudCorrelationEngine

class CyberFraudPlatform:
    """Main platform orchestrator that integrates all components"""
    
    def __init__(self, config_file: str = 'platform_config.json'):
        self.config = self._load_config(config_file)
        self.db_path = 'cyber_fraud_platform.db'
        
        # Initialize platform components
        self._initialize_components()
        self._setup_schedules()
        
        print("🚀 Cyber-Fraud Intelligence Platform Initialized")
    
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Load platform configuration"""
        default_config = {
            'modules': {
                'threat_intel': True,
                'fraud_detection': True,
                'sanction_screening': True,
                'correlation_engine': True
            },
            'scheduling': {
                'threat_intel_interval_hours': 24,
                'sanction_update_interval_hours': 168,  # Weekly
                'correlation_interval_hours': 6
            },
            'alerting': {
                'high_risk_threshold': 0.7,
                'enable_real_time_alerts': True
            }
        }
        
        try:
            with open(config_file, 'r') as f:
                user_config = json.load(f)
                self._deep_merge(default_config, user_config)
        except FileNotFoundError:
            print(f"⚠️  Platform config not found at {config_file}. Using defaults.")
        
        return default_config
    
    def _deep_merge(self, default: Dict, user: Dict) -> None:
        """Recursively merge configurations"""
        for key, value in user.items():
            if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                self._deep_merge(default[key], value)
            else:
                default[key] = value
    
    def _initialize_components(self) -> None:
        """Initialize all platform components"""
        print("🔄 Initializing platform components...")
        
        # Threat Intelligence & Fraud Detection
        self.scraper = FraudPatternScraper()
        self.pattern_detector = PatternDetector()
        
        # Sanction Screening
        self.sanction_screener = IntegratedSanctionScreener(self.db_path)
        
        # Correlation Engine
        self.correlation_engine = CyberFraudCorrelationEngine(self.db_path)
        
        # Alert Management
        self.alert_manager = UnifiedAlertManager()
        
        print("✅ All components initialized")
    
    # def _setup_schedules(self) -> None:
    #     """Setup automated schedules for platform operations"""
    #     scheduling = self.config['scheduling']
        
    #     # Daily threat intelligence collection
    #     schedule.every(scheduling['threat_intel_interval_hours']).hours.do(
    #         self.run_threat_intelligence_collection
    #     )
        
    #     # Weekly sanction list updates
    #     schedule.every(scheduling['sanction_update_interval_hours']).hours.do(
    #         self.sanction_screener.download_sanction_lists
    #     )
        
    #     # Regular correlation analysis
    #     schedule.every(scheduling['correlation_interval_hours']).hours.do(
    #         self.run_correlation_analysis
    #     )
        
    #     # Daily comprehensive report
    #     schedule.every().day.at("06:00").do(
    #         self.generate_daily_comprehensive_report
    #     )
        
    #     print("✅ Automated schedules configured")
    

    def _setup_schedules(self) -> None:
       """Setup automated schedules for platform operations"""
       scheduling = self.config['scheduling']
    
       # Daily threat intelligence collection
       schedule.every(scheduling['threat_intel_interval_hours']).hours.do(
        self.run_threat_intelligence_collection
       )
    
       # Weekly sanction list updates
       schedule.every(scheduling['sanction_update_interval_hours']).hours.do(
        self.sanction_screener.download_sanction_lists
      )
    
       # Regular correlation analysis
       schedule.every(scheduling['correlation_interval_hours']).hours.do(
         self.run_correlation_analysis
      )
    
       # Daily comprehensive report - FIXED: use the correct method name
       schedule.every().day.at("06:00").do(
         self.run_daily_operations  # ← Changed to run_daily_operations which includes report generation
     )
    
       print("✅ Automated schedules configured")


    def run_daily_operations(self) -> Dict[str, Any]:
        """
        Execute complete daily platform operations
        
        Returns:
            Dictionary containing results from all modules
        """
        print("\n" + "="*60)
        print("🚀 STARTING CYBER-FRAUD PLATFORM DAILY OPERATIONS")
        print("="*60)
        
        results = {}
        
        try:
            # Phase 1: Threat Intelligence Collection
            if self.config['modules']['threat_intel']:
                print("\n--- PHASE 1: THREAT INTELLIGENCE COLLECTION ---")
                results['threat_intel'] = self.run_threat_intelligence_collection()
            
            # Phase 2: Fraud Pattern Analysis
            if self.config['modules']['fraud_detection']:
                print("\n--- PHASE 2: FRAUD PATTERN ANALYSIS ---")
                results['fraud_analysis'] = self.analyze_fraud_patterns(
                    results.get('threat_intel', [])
                )
            
            # Phase 3: Sanction Screening Updates
            if self.config['modules']['sanction_screening']:
                print("\n--- PHASE 3: SANCTION SCREENING UPDATES ---")
                results['sanction_updates'] = self.update_sanction_screening()
            
            # Phase 4: Correlation Analysis
            if self.config['modules']['correlation_engine']:
                print("\n--- PHASE 4: CORRELATION ANALYSIS ---")
                results['correlation_analysis'] = self.run_correlation_analysis()
            
            # Phase 5: Generate Comprehensive Report
            print("\n--- PHASE 5: REPORTING & ALERTING ---")
            report_file = self.generate_comprehensive_report(results)
            results['report_file'] = report_file
            
            # Send summary alert
            self.send_operations_summary(results)
            
            print("\n✅ DAILY OPERATIONS COMPLETED SUCCESSFULLY")
            
        except Exception as e:
            print(f"\n❌ PLATFORM OPERATIONS FAILED: {e}")
            # Send error alert
            self.alert_manager.send_comprehensive_alert('platform_error', {
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            })
        
        return results
    
    def run_threat_intelligence_collection(self) -> List[Dict[str, Any]]:
        """Execute threat intelligence collection"""
        print("🕵️  Collecting threat intelligence from all sources...")
        return self.scraper.scrape_all_sources()
    
    def analyze_fraud_patterns(self, threat_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze fraud patterns in collected threat intelligence"""
        print("🔍 Analyzing fraud patterns in threat data...")
        
        analysis_results = []
        total_scenarios = 0
        high_confidence_count = 0
        
        for item in threat_data:
            analysis_text = f"{item.get('title', '')} {item.get('content', '')}"
            patterns = self.pattern_detector.detect_patterns(analysis_text)
            
            if patterns:
                scenarios = []
                for pattern in patterns:
                    scenario = self.pattern_detector.generate_clari5_scenario(pattern, item)
                    scenarios.append(scenario)
                    total_scenarios += 1
                    
                    if scenario.get('confidence_score', 0) >= self.config['alerting']['high_risk_threshold']:
                        high_confidence_count += 1
                
                analysis_results.append({
                    'source_item': item,
                    'detected_patterns': patterns,
                    'generated_scenarios': scenarios,
                    'iocs': self.pattern_detector.extract_iocs(analysis_text)
                })
        
        # Send fraud alerts if high-confidence scenarios found
        if high_confidence_count > 0 and self.config['alerting']['enable_real_time_alerts']:
            self.alert_manager.send_comprehensive_alert('fraud', {
                'patterns_detected': len(analysis_results),
                'scenarios_generated': total_scenarios,
                'high_confidence': high_confidence_count,
                'pattern_breakdown': self._summarize_patterns(analysis_results)
            })
        
        return {
            'analysis_results': analysis_results,
            'summary': {
                'items_analyzed': len(threat_data),
                'patterns_detected': len(analysis_results),
                'scenarios_generated': total_scenarios,
                'high_confidence_scenarios': high_confidence_count
            }
        }
    
    def update_sanction_screening(self) -> Dict[str, Any]:
        """Update sanction lists and perform screenings"""
        print("🔄 Updating sanction screening data...")
        
        # Download latest sanction lists
        self.sanction_screener.download_sanction_lists()
        
        # Get screening statistics
        cursor = self.sanction_screener.db_conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM sanction_entities')
        sanction_count = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT COUNT(*) FROM sanction_screening_results 
            WHERE screening_date > date('now', '-1 day')
        ''')
        daily_screenings = cursor.fetchone()[0]
        
        return {
            'sanction_entities_count': sanction_count,
            'daily_screenings': daily_screenings,
            'last_updated': datetime.now().isoformat()
        }
    
    def run_correlation_analysis(self) -> Dict[str, Any]:
        """Execute cyber-fraud correlation analysis"""
        print("🔗 Running cyber-fraud correlation analysis...")
        
        try:
            correlations = self.correlation_engine.analyze_recent_activity()
            
            # Send alerts for high-confidence correlations
            high_risk_correlations = [
                corr for corr in correlations 
                if corr.get('correlation_score', 0) >= self.config['alerting']['high_risk_threshold']
            ]
            
            for correlation in high_risk_correlations:
                self.alert_manager.send_comprehensive_alert('correlation', correlation)
            
            return {
                'total_correlations': len(correlations),
                'high_risk_correlations': len(high_risk_correlations),
                'correlations': correlations[:10]  # Return top 10
            }
            
        except Exception as e:
            print(f"❌ Correlation analysis failed: {e}")
            return {'error': str(e)}
    
    def process_customer_onboarding(self, customer_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process new customer through all security checks
        
        Args:
            customer_data: Customer information for screening
            
        Returns:
            Comprehensive screening results
        """
        print(f"👤 Processing customer onboarding: {customer_data.get('name', 'Unknown')}")
        
        results = {}
        
        # Sanction Screening
        results['sanction_screening'] = self.sanction_screener.screen_customer_onboarding(customer_data)
        
        # Fraud Risk Assessment
        fraud_patterns = self.pattern_detector.detect_customer_risk(customer_data)
        results['fraud_risk'] = {
            'risk_score': self._calculate_fraud_risk_score(fraud_patterns),
            'detected_patterns': fraud_patterns
        }
        
        # Cyber Risk Assessment
        results['cyber_risk'] = self.correlation_engine.assess_customer_cyber_risk(customer_data)
        
        # Update customer risk profile
        self._update_customer_risk_profile(customer_data['customer_id'], results)
        
        # Send onboarding alert if high risk
        if (len(results['sanction_screening']) > 0 or 
            results['fraud_risk']['risk_score'] > 70):
            
            self.alert_manager.send_comprehensive_alert('sanction', {
                'customer_name': customer_data['name'],
                'customer_id': customer_data['customer_id'],
                'sanction_matches': len(results['sanction_screening']),
                'fraud_risk_score': results['fraud_risk']['risk_score'],
                'screening_type': 'onboarding'
            })
        
        return results
    
    def generate_comprehensive_report(self, operations_results: Dict[str, Any]) -> str:
        """Generate comprehensive platform report"""
        print("📊 Generating comprehensive platform report...")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_data = {
            'metadata': {
                'platform_version': '2.0.0',
                'generation_time': datetime.now().isoformat(),
                'report_id': f"CFP_REPORT_{timestamp}"
            },
            'executive_summary': self._generate_executive_summary(operations_results),
            'module_results': operations_results,
            'recommendations': self._generate_recommendations(operations_results)
        }
        
        filename = f"platform_comprehensive_report_{timestamp}.json"
        with open(f"research_outputs/{filename}", 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Comprehensive report saved: {filename}")
        return filename
    
    def send_operations_summary(self, results: Dict[str, Any]) -> None:
        """Send summary of daily operations"""
        summary = self._generate_operations_summary(results)
        self.alert_manager.send_comprehensive_alert('platform_daily_report', summary)
    
    def _summarize_patterns(self, analysis_results: List[Dict]) -> Dict[str, int]:
        """Summarize detected patterns"""
        pattern_counts = {}
        for result in analysis_results:
            for pattern in result['detected_patterns']:
                pattern_name = pattern['pattern']
                pattern_counts[pattern_name] = pattern_counts.get(pattern_name, 0) + 1
        return pattern_counts
    
    def _calculate_fraud_risk_score(self, fraud_patterns: List[Dict]) -> float:
        """Calculate fraud risk score from patterns"""
        if not fraud_patterns:
            return 0.0
        
        total_confidence = sum(pattern.get('confidence', 0) for pattern in fraud_patterns)
        return min((total_confidence / len(fraud_patterns)) * 100, 100)
    
    def _update_customer_risk_profile(self, customer_id: str, results: Dict[str, Any]) -> None:
        """Update customer risk profile in database"""
        try:
            cursor = self.sanction_screener.db_conn.cursor()
            
            fraud_score = results['fraud_risk']['risk_score']
            cyber_score = results['cyber_risk'].get('risk_score', 0)
            sanction_matches = len(results['sanction_screening'])
            
            cursor.execute('''
                INSERT OR REPLACE INTO customers 
                (customer_id, fraud_risk_score, cyber_risk_score, sanction_matches, last_updated)
                VALUES (?, ?, ?, ?, ?)
            ''', (customer_id, fraud_score, cyber_score, sanction_matches, datetime.now()))
            
            self.sanction_screener.db_conn.commit()
            
        except Exception as e:
            print(f"❌ Failed to update customer risk profile: {e}")
    
    def _generate_executive_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary from operations results"""
        threat_intel = results.get('threat_intel', [])
        fraud_analysis = results.get('fraud_analysis', {})
        correlation = results.get('correlation_analysis', {})
        
        return {
            'threat_intelligence_sources': len(set(item.get('source') for item in threat_intel)),
            'threat_items_collected': len(threat_intel),
            'fraud_patterns_detected': fraud_analysis.get('summary', {}).get('patterns_detected', 0),
            'high_risk_scenarios': fraud_analysis.get('summary', {}).get('high_confidence_scenarios', 0),
            'cyber_fraud_correlations': correlation.get('high_risk_correlations', 0),
            'platform_health': 'OPERATIONAL',
            'generation_time': datetime.now().isoformat()
        }
    
    def _generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on analysis results"""
        recommendations = []
        
        fraud_scenarios = results.get('fraud_analysis', {}).get('summary', {}).get('high_confidence_scenarios', 0)
        if fraud_scenarios > 5:
            recommendations.append("Consider enhancing transaction monitoring rules for detected fraud patterns")
        
        correlations = results.get('correlation_analysis', {}).get('high_risk_correlations', 0)
        if correlations > 0:
            recommendations.append("Review high-risk cyber-fraud correlations for potential systemic issues")
        
        if not recommendations:
            recommendations.append("No immediate action required - platform operating within normal parameters")
        
        return recommendations
    
    def _generate_operations_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate operations summary for alerts"""
        return {
            'daily_operations_completed': True,
            'threat_intel_items': len(results.get('threat_intel', [])),
            'fraud_patterns': results.get('fraud_analysis', {}).get('summary', {}).get('patterns_detected', 0),
            'high_risk_findings': results.get('fraud_analysis', {}).get('summary', {}).get('high_confidence_scenarios', 0),
            'cyber_fraud_correlations': results.get('correlation_analysis', {}).get('high_risk_correlations', 0),
            'report_file': results.get('report_file', ''),
            'timestamp': datetime.now().isoformat()
        }
    
    def start_continuous_operations(self) -> None:
        """Start continuous platform operations with scheduling"""
        print("🔄 Starting continuous platform operations...")
        print("Platform will run scheduled tasks automatically")
        print("Press Ctrl+C to stop")
        
        try:
            while True:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
        except KeyboardInterrupt:
            print("\n🛑 Platform operations stopped by user")

def main():
    """Main execution function"""
    platform = CyberFraudPlatform()
    
    # Run daily operations
    results = platform.run_daily_operations()
    
    # Start continuous operations (optional)
    # platform.start_continuous_operations()

if __name__ == "__main__":
    main()