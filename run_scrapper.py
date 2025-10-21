from core_scraper import FraudPatternScraper
from pattern_detector import PatternDetector
import json
from datetime import datetime
from alert_manager import AlertManager

def main():
    print("=== ENHANCED Automated Fraud Pattern Research Tool ===")
    print("Starting comprehensive data collection and analysis...")
    
    # Initialize enhanced components
    scraper = FraudPatternScraper()
    detector = PatternDetector()
    
    # Run enhanced scraping
    print("\n--- Data Collection Phase ---")
    raw_data = scraper.scrape_all_sources()
    
    # Enhanced pattern analysis
    print("\n--- Pattern Analysis Phase ---")
    analysis_results = []
    scenarios_generated = 0
    high_confidence_scenarios = 0
    
    for item in raw_data:
        analysis_text = f"{item.get('title', '')} {item.get('content', '')}"
        
        # Detect patterns with enhanced algorithm
        patterns = detector.detect_patterns(analysis_text)
        
        # Generate scenarios for detected patterns
        item_scenarios = []
        for pattern in patterns:
            scenario = detector.generate_clari5_scenario(pattern, item)
            item_scenarios.append(scenario)
            scenarios_generated += 1
            
            # Count high confidence scenarios
            if scenario['confidence_score'] >= 0.7:
                high_confidence_scenarios += 1
        
        analysis_results.append({
            'original_item': item,
            'detected_patterns': patterns,
            'generated_scenarios': item_scenarios,
            'iocs': detector.extract_iocs(analysis_text)
        })
    
    # Generate comprehensive report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_data = {
        'metadata': {
            'generated_at': datetime.now().isoformat(),
            'total_sources': len(set(item['source'] for item in raw_data)),
            'total_items': len(raw_data),
            'scenarios_generated': scenarios_generated,
            'high_confidence_scenarios': high_confidence_scenarios,
            'tool_version': '2.0 - Enhanced'
        },
        'raw_data': raw_data,
        'analysis_results': analysis_results,
        'executive_summary': generate_executive_summary(analysis_results)
    }
    
    filename = f"enhanced_fraud_research_{timestamp}.json"
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)

    
    # New functionality added here for alerting and dashboard
   
    # Generate enhanced report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"enhanced_fraud_research_{timestamp}.json"
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)
    
    # Alerting and Dashboard
    print("\n--- Alerting & Dashboard Phase ---")
    try:
        alert_manager = AlertManager()
        high_risk_findings = alert_manager.generate_alert_summary(output_data)
        
        if high_risk_findings:
            print(f"🚨 High-Risk Findings: {len(high_risk_findings)} scenarios above threshold")
            alert_manager.send_email_alert(high_risk_findings)
        
        # Generate dashboard data
        dashboard_data = alert_manager.generate_dashboard_data(output_data)
        dashboard_file = f"dashboard_data_{timestamp}.json"
        with open(dashboard_file, 'w') as f:
            json.dump(dashboard_data, f, indent=2)
        print(f"📊 Dashboard data saved: {dashboard_file}")
        
    except Exception as e:
        print(f"Alerting system error: {e}")










    
    # Print enhanced summary
    print(f"\n=== ENHANCED RESEARCH SUMMARY ===")
    print(f"Data Sources: {output_data['metadata']['total_sources']}")
    print(f"Items Analyzed: {len(raw_data)}")
    print(f"Fraud Patterns Detected: {output_data['executive_summary']['total_patterns']}")
    print(f"Scenarios Generated: {scenarios_generated}")
    print(f"High-Confidence Scenarios: {high_confidence_scenarios}")
    
    # Pattern breakdown with confidence levels
    print(f"\nPattern Analysis:")
    for pattern, count in output_data['executive_summary']['pattern_breakdown'].items():
        print(f"  {pattern}: {count}")
    
    # Risk distribution
    print(f"\nRisk Distribution:")
    for risk, count in output_data['executive_summary']['risk_distribution'].items():
        print(f"  {risk} Risk: {count}")
    
    print(f"\nFull enhanced analysis saved to: {filename}")
    print("Enhanced research complete!")

def generate_executive_summary(analysis_results):
    """Generate executive summary of findings"""
    total_patterns = sum(len(result['detected_patterns']) for result in analysis_results)
    
    pattern_breakdown = {}
    risk_distribution = {'High': 0, 'Medium': 0, 'Low': 0}
    confidence_scores = []
    
    for result in analysis_results:
        for pattern in result['detected_patterns']:
            pattern_name = pattern['pattern']
            pattern_breakdown[pattern_name] = pattern_breakdown.get(pattern_name, 0) + 1
            risk_distribution[pattern['risk_level']] = risk_distribution.get(pattern['risk_level'], 0) + 1
            confidence_scores.append(pattern['confidence'])
    
    avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0
    
    return {
        'total_patterns': total_patterns,
        'pattern_breakdown': pattern_breakdown,
        'risk_distribution': risk_distribution,
        'average_confidence': round(avg_confidence, 2),
        'high_confidence_rate': len([c for c in confidence_scores if c >= 0.7]) / len(confidence_scores) if confidence_scores else 0
    }

if __name__ == "__main__":
    main()