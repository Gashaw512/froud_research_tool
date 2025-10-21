import json
import os
from datetime import datetime

def generate_html_dashboard(json_file_path):
    """Generate a simple HTML dashboard from the JSON data"""
    
    with open(json_file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Fraud Pattern Research Dashboard</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .card {{ border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }}
            .high-risk {{ border-left: 5px solid #e74c3c; }}
            .medium-risk {{ border-left: 5px solid #f39c12; }}
            .summary {{ background: #f8f9fa; padding: 15px; }}
            .pattern {{ display: inline-block; background: #3498db; color: white; padding: 5px 10px; margin: 2px; border-radius: 3px; }}
        </style>
    </head>
    <body>
        <h1>🚨 Fraud Pattern Research Dashboard</h1>
        <p>Generated: {data['metadata']['generated_at']}</p>
        
        <div class="card summary">
            <h2>Executive Summary</h2>
            <p><strong>Items Analyzed:</strong> {data['metadata']['total_items']}</p>
            <p><strong>Patterns Detected:</strong> {data['executive_summary']['total_patterns']}</p>
            <p><strong>Scenarios Generated:</strong> {data['metadata']['scenarios_generated']}</p>
            <p><strong>High-Confidence Scenarios:</strong> {data['metadata']['high_confidence_scenarios']}</p>
        </div>
        
        <div class="card">
            <h2>Pattern Distribution</h2>
    """
    
    for pattern, count in data['executive_summary']['pattern_breakdown'].items():
        html_content += f'<span class="pattern">{pattern}: {count}</span>'
    
    html_content += """
        </div>
        
        <div class="card">
            <h2>Top High-Risk Scenarios</h2>
    """
    
    # Get all scenarios and sort by confidence
    all_scenarios = []
    for result in data['analysis_results']:
        all_scenarios.extend(result['generated_scenarios'])
    
    all_scenarios.sort(key=lambda x: x['confidence_score'], reverse=True)
    
    for i, scenario in enumerate(all_scenarios[:5]):
        risk_class = "high-risk" if scenario['risk_level'] == 'High' else "medium-risk"
        html_content += f"""
            <div class="card {risk_class}">
                <h3>{scenario['title']} (Confidence: {scenario['confidence_score']})</h3>
                <p><strong>Clari5 Scenario:</strong> {scenario['scenario_type']}</p>
                <p><strong>Source:</strong> {scenario['source_reference']['source']} - {scenario['source_reference']['title']}</p>
                <p><strong>Description:</strong> {scenario['description']}</p>
            </div>
        """
    
    html_content += """
        </div>
    </body>
    </html>
    """
    
    dashboard_file = json_file_path.replace('.json', '_dashboard.html')
    with open(dashboard_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"📈 HTML Dashboard generated: {dashboard_file}")
    return dashboard_file

if __name__ == "__main__":
    # Find the latest research file
    import glob
    files = glob.glob('enhanced_fraud_research_*.json')
    if files:
        latest_file = max(files, key=os.path.getctime)
        generate_html_dashboard(latest_file)
    else:
        print("No research files found. Run the scraper first.")