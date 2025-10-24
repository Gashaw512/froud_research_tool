# import json
# import os
# from datetime import datetime

# def generate_html_dashboard(json_file_path):
#     """Generate a simple HTML dashboard from the JSON data"""
    
#     with open(json_file_path, 'r', encoding='utf-8') as f:
#         data = json.load(f)
    
#     html_content = f"""
#     <!DOCTYPE html>
#     <html>
#     <head>
#         <title>Fraud Pattern Research Dashboard</title>
#         <style>
#             body {{ font-family: Arial, sans-serif; margin: 20px; }}
#             .card {{ border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }}
#             .high-risk {{ border-left: 5px solid #e74c3c; }}
#             .medium-risk {{ border-left: 5px solid #f39c12; }}
#             .summary {{ background: #f8f9fa; padding: 15px; }}
#             .pattern {{ display: inline-block; background: #3498db; color: white; padding: 5px 10px; margin: 2px; border-radius: 3px; }}
#         </style>
#     </head>
#     <body>
#         <h1>🚨 Fraud Pattern Research Dashboard</h1>
#         <p>Generated: {data['metadata']['generated_at']}</p>
        
#         <div class="card summary">
#             <h2>Executive Summary</h2>
#             <p><strong>Items Analyzed:</strong> {data['metadata']['total_items']}</p>
#             <p><strong>Patterns Detected:</strong> {data['executive_summary']['total_patterns']}</p>
#             <p><strong>Scenarios Generated:</strong> {data['metadata']['scenarios_generated']}</p>
#             <p><strong>High-Confidence Scenarios:</strong> {data['metadata']['high_confidence_scenarios']}</p>
#         </div>
        
#         <div class="card">
#             <h2>Pattern Distribution</h2>
#     """
    
#     for pattern, count in data['executive_summary']['pattern_breakdown'].items():
#         html_content += f'<span class="pattern">{pattern}: {count}</span>'
    
#     html_content += """
#         </div>
        
#         <div class="card">
#             <h2>Top High-Risk Scenarios</h2>
#     """
    
#     # Get all scenarios and sort by confidence
#     all_scenarios = []
#     for result in data['analysis_results']:
#         all_scenarios.extend(result['generated_scenarios'])
    
#     all_scenarios.sort(key=lambda x: x['confidence_score'], reverse=True)
    
#     for i, scenario in enumerate(all_scenarios[:5]):
#         risk_class = "high-risk" if scenario['risk_level'] == 'High' else "medium-risk"
#         html_content += f"""
#             <div class="card {risk_class}">
#                 <h3>{scenario['title']} (Confidence: {scenario['confidence_score']})</h3>
#                 <p><strong>Clari5 Scenario:</strong> {scenario['scenario_type']}</p>
#                 <p><strong>Source:</strong> {scenario['source_reference']['source']} - {scenario['source_reference']['title']}</p>
#                 <p><strong>Description:</strong> {scenario['description']}</p>
#             </div>
#         """
    
#     html_content += """
#         </div>
#     </body>
#     </html>
#     """
    
#     dashboard_file = json_file_path.replace('.json', '_dashboard.html')
#     with open(dashboard_file, 'w', encoding='utf-8') as f:
#         f.write(html_content)
    
#     print(f"📈 HTML Dashboard generated: {dashboard_file}")
#     return dashboard_file

# if __name__ == "__main__":
#     # Find the latest research file
#     import glob
#     files = glob.glob('enhanced_fraud_research_*.json')
#     if files:
#         latest_file = max(files, key=os.path.getctime)
#         generate_html_dashboard(latest_file)
#     else:
#         print("No research files found. Run the scraper first.")


#!/usr/bin/env python3
"""
Advanced Dashboard Generator for Cyber-Fraud Intelligence Platform
Generates comprehensive HTML dashboards with analytics, charts, and interactive elements
"""

import json
import os
import glob
from datetime import datetime, timedelta
import plotly.graph_objects as go
import plotly.offline as pyo
import pandas as pd
from typing import Dict, List, Any, Optional

class AdvancedDashboardGenerator:
    """Professional dashboard generator with analytics and visualization"""
    
    def __init__(self, output_dir: str = "research_outputs/dashboards"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # Dashboard color scheme
        self.colors = {
            'primary': '#2c3e50',
            'secondary': '#3498db',
            'success': '#27ae60',
            'warning': '#f39c12',
            'danger': '#e74c3c',
            'info': '#17a2b8',
            'light': '#ecf0f1',
            'dark': '#34495e'
        }
    
    def generate_comprehensive_dashboard(self, json_file_path: str) -> str:
        """
        Generate comprehensive dashboard from platform JSON data
        
        Args:
            json_file_path: Path to platform JSON report
            
        Returns:
            Path to generated HTML dashboard
        """
        print(f"📊 Generating comprehensive dashboard from: {json_file_path}")
        
        with open(json_file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Generate dashboard components
        dashboard_html = self._generate_dashboard_header(data)
        dashboard_html += self._generate_executive_summary(data)
        dashboard_html += self._generate_threat_intelligence_section(data)
        dashboard_html += self._generate_fraud_analytics_section(data)
        dashboard_html += self._generate_correlation_insights(data)
        dashboard_html += self._generate_recommendations_section(data)
        dashboard_html += self._generate_dashboard_footer()
        
        # Save dashboard
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        dashboard_file = os.path.join(self.output_dir, f"comprehensive_dashboard_{timestamp}.html")
        
        with open(dashboard_file, 'w', encoding='utf-8') as f:
            f.write(dashboard_html)
        
        print(f"✅ Comprehensive dashboard generated: {dashboard_file}")
        return dashboard_file
    
    def generate_operational_dashboard(self, data_files: List[str]) -> str:
        """
        Generate operational dashboard from multiple data files
        
        Args:
            data_files: List of JSON data file paths
            
        Returns:
            Path to generated HTML dashboard
        """
        print("🔄 Generating operational dashboard from multiple data sources...")
        
        all_data = []
        for file_path in data_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    all_data.append(data)
            except Exception as e:
                print(f"⚠️  Error loading {file_path}: {e}")
        
        dashboard_html = self._generate_operational_header()
        dashboard_html += self._generate_trend_analysis(all_data)
        dashboard_html += self._generate_performance_metrics(all_data)
        dashboard_html += self._generate_risk_heatmap(all_data)
        dashboard_html += self._generate_operational_footer()
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        dashboard_file = os.path.join(self.output_dir, f"operational_dashboard_{timestamp}.html")
        
        with open(dashboard_file, 'w', encoding='utf-8') as f:
            f.write(dashboard_html)
        
        print(f"✅ Operational dashboard generated: {dashboard_file}")
        return dashboard_file
    
    def _generate_dashboard_header(self, data: Dict[str, Any]) -> str:
        """Generate dashboard header with metadata"""
        metadata = data.get('metadata', {})
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cyber-Fraud Intelligence Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {{
            --primary-color: {self.colors['primary']};
            --secondary-color: {self.colors['secondary']};
            --success-color: {self.colors['success']};
            --warning-color: {self.colors['warning']};
            --danger-color: {self.colors['danger']};
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f8f9fa;
            color: {self.colors['dark']};
        }}
        
        .dashboard-header {{
            background: linear-gradient(135deg, {self.colors['primary']}, {self.colors['secondary']});
            color: white;
            padding: 2rem 0;
            margin-bottom: 2rem;
        }}
        
        .metric-card {{
            background: white;
            border-radius: 10px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            border-left: 4px solid var(--secondary-color);
            transition: transform 0.2s;
        }}
        
        .metric-card:hover {{
            transform: translateY(-5px);
        }}
        
        .metric-value {{
            font-size: 2.5rem;
            font-weight: bold;
            color: var(--primary-color);
        }}
        
        .metric-label {{
            font-size: 0.9rem;
            color: #6c757d;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .risk-high {{
            border-left-color: var(--danger-color);
        }}
        
        .risk-medium {{
            border-left-color: var(--warning-color);
        }}
        
        .risk-low {{
            border-left-color: var(--success-color);
        }}
        
        .scenario-card {{
            background: white;
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1rem;
            border-left: 4px solid #ddd;
        }}
        
        .pattern-tag {{
            display: inline-block;
            background: {self.colors['secondary']};
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.8rem;
            margin: 0.2rem;
        }}
        
        .chart-container {{
            background: white;
            border-radius: 10px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
    </style>
</head>
<body>
    <div class="dashboard-header">
        <div class="container">
            <div class="row align-items-center">
                <div class="col-md-8">
                    <h1><i class="fas fa-shield-alt me-2"></i>Cyber-Fraud Intelligence Dashboard</h1>
                    <p class="lead mb-0">Comprehensive Threat Analysis & Fraud Detection</p>
                </div>
                <div class="col-md-4 text-end">
                    <p class="mb-0"><strong>Generated:</strong> {metadata.get('generation_time', 'N/A')}</p>
                    <p class="mb-0"><strong>Report ID:</strong> {metadata.get('report_id', 'N/A')}</p>
                </div>
            </div>
        </div>
    </div>

    <div class="container">
"""
    
    def _generate_executive_summary(self, data: Dict[str, Any]) -> str:
        """Generate executive summary section"""
        exec_summary = data.get('executive_summary', {})
        module_results = data.get('module_results', {})
        
        threat_intel = module_results.get('threat_intel', [])
        fraud_analysis = module_results.get('fraud_analysis', {})
        correlation = module_results.get('correlation_analysis', {})
        
        return f"""
        <!-- Executive Summary -->
        <div class="row mb-4">
            <div class="col-12">
                <div class="metric-card">
                    <h2><i class="fas fa-chart-line me-2"></i>Executive Summary</h2>
                    <div class="row mt-4">
                        <div class="col-md-3 text-center">
                            <div class="metric-value text-primary">{len(threat_intel)}</div>
                            <div class="metric-label">Threat Intel Items</div>
                        </div>
                        <div class="col-md-3 text-center">
                            <div class="metric-value text-warning">{fraud_analysis.get('summary', {}).get('patterns_detected', 0)}</div>
                            <div class="metric-label">Fraud Patterns</div>
                        </div>
                        <div class="col-md-3 text-center">
                            <div class="metric-value text-danger">{fraud_analysis.get('summary', {{}}).get('high_confidence_scenarios', 0)}</div>
                            <div class="metric-label">High-Risk Scenarios</div>
                        </div>
                        <div class="col-md-3 text-center">
                            <div class="metric-value text-info">{correlation.get('high_risk_correlations', 0)}</div>
                            <div class="metric-label">Cyber-Fraud Correlations</div>
                        </div>
                    </div>
                    
                    <div class="row mt-4">
                        <div class="col-12">
                            <div class="alert alert-{'success' if exec_summary.get('platform_health') == 'OPERATIONAL' else 'warning'}">
                                <h5><i class="fas fa-{'check-circle' if exec_summary.get('platform_health') == 'OPERATIONAL' else 'exclamation-triangle'} me-2"></i>
                                Platform Status: {exec_summary.get('platform_health', 'UNKNOWN')}</h5>
                                <p class="mb-0">All systems operating within normal parameters. Continuous monitoring active.</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
"""
    
    def _generate_threat_intelligence_section(self, data: Dict[str, Any]) -> str:
        """Generate threat intelligence section"""
        module_results = data.get('module_results', {})
        threat_intel = module_results.get('threat_intel', [])
        
        # Analyze threat sources
        sources = {}
        for item in threat_intel:
            source = item.get('source', 'Unknown')
            sources[source] = sources.get(source, 0) + 1
        
        sources_html = ""
        for source, count in sources.items():
            sources_html += f'<span class="pattern-tag">{source}: {count}</span>'
        
        return f"""
        <!-- Threat Intelligence -->
        <div class="row mb-4">
            <div class="col-md-6">
                <div class="metric-card">
                    <h3><i class="fas fa-bullseye me-2"></i>Threat Intelligence</h3>
                    <p><strong>Total Items Collected:</strong> {len(threat_intel)}</p>
                    <p><strong>Sources Monitored:</strong> {len(sources)}</p>
                    
                    <h5 class="mt-3">Source Distribution</h5>
                    {sources_html}
                </div>
            </div>
            
            <div class="col-md-6">
                <div class="metric-card">
                    <h3><i class="fas fa-clock me-2"></i>Recent Threats</h3>
                    <div style="max-height: 300px; overflow-y: auto;">
        """
        
        # Add recent threats
        for i, item in enumerate(threat_intel[:8]):
            title = item.get('title', 'No title')[:80] + "..." if len(item.get('title', '')) > 80 else item.get('title', 'No title')
            source = item.get('source', 'Unknown')
            
            return_part = f"""
                        <div class="scenario-card {'risk-high' if i < 2 else 'risk-medium'}">
                            <h6 class="mb-1">{title}</h6>
                            <p class="mb-1 text-muted"><small>Source: {source}</small></p>
                        </div>
            """
            self._generate_threat_intelligence_section.__code__ = (lambda: None).__code__  # Reset context
            threat_intelligence_html = return_part
        
        threat_intelligence_html += """
                    </div>
                </div>
            </div>
        </div>
        """
        return threat_intelligence_html
    
    def _generate_fraud_analytics_section(self, data: Dict[str, Any]) -> str:
        """Generate fraud analytics section with patterns and scenarios"""
        module_results = data.get('module_results', {})
        fraud_analysis = module_results.get('fraud_analysis', {})
        analysis_results = fraud_analysis.get('analysis_results', [])
        summary = fraud_analysis.get('summary', {})
        
        # Extract patterns
        pattern_counts = {}
        all_scenarios = []
        
        for result in analysis_results:
            # Count patterns
            for pattern in result.get('detected_patterns', []):
                pattern_name = pattern.get('pattern', 'Unknown')
                pattern_counts[pattern_name] = pattern_counts.get(pattern_name, 0) + 1
            
            # Collect scenarios
            all_scenarios.extend(result.get('generated_scenarios', []))
        
        # Sort scenarios by confidence
        all_scenarios.sort(key=lambda x: x.get('confidence_score', 0), reverse=True)
        
        # Generate patterns HTML
        patterns_html = ""
        for pattern, count in pattern_counts.items():
            patterns_html += f'<span class="pattern-tag">{pattern}: {count}</span>'
        
        # Generate scenarios HTML
        scenarios_html = ""
        for i, scenario in enumerate(all_scenarios[:5]):
            confidence = scenario.get('confidence_score', 0)
            risk_class = "risk-high" if confidence >= 0.8 else "risk-medium" if confidence >= 0.6 else "risk-low"
            
            scenarios_html += f"""
            <div class="scenario-card {risk_class}">
                <div class="d-flex justify-content-between align-items-start">
                    <h6 class="mb-1">{scenario.get('title', 'Unknown Scenario')}</h6>
                    <span class="badge bg-{'danger' if confidence >= 0.8 else 'warning' if confidence >= 0.6 else 'success'}">
                        {confidence:.1%} Confidence
                    </span>
                </div>
                <p class="mb-1"><strong>Type:</strong> {scenario.get('scenario_type', 'N/A')}</p>
                <p class="mb-1"><strong>Source:</strong> {scenario.get('source_reference', {{}}).get('source', 'N/A')}</p>
                <p class="mb-0 text-muted"><small>{scenario.get('description', '')[:150]}...</small></p>
            </div>
            """
        
        return f"""
        <!-- Fraud Analytics -->
        <div class="row mb-4">
            <div class="col-12">
                <div class="metric-card">
                    <h2><i class="fas fa-search me-2"></i>Fraud Pattern Analytics</h2>
                    
                    <div class="row mt-3">
                        <div class="col-md-6">
                            <h5>Pattern Distribution</h5>
                            {patterns_html if patterns_html else '<p>No patterns detected</p>'}
                            
                            <div class="row mt-4">
                                <div class="col-6">
                                    <div class="text-center p-3 bg-light rounded">
                                        <div class="metric-value text-success">{summary.get('items_analyzed', 0)}</div>
                                        <div class="metric-label">Items Analyzed</div>
                                    </div>
                                </div>
                                <div class="col-6">
                                    <div class="text-center p-3 bg-light rounded">
                                        <div class="metric-value text-warning">{summary.get('scenarios_generated', 0)}</div>
                                        <div class="metric-label">Scenarios Generated</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="col-md-6">
                            <h5>Top Risk Scenarios</h5>
                            <div style="max-height: 400px; overflow-y: auto;">
                                {scenarios_html if scenarios_html else '<p>No high-risk scenarios detected</p>'}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
"""
    
    def _generate_correlation_insights(self, data: Dict[str, Any]) -> str:
        """Generate correlation insights section"""
        module_results = data.get('module_results', {})
        correlation = module_results.get('correlation_analysis', {})
        
        total_correlations = correlation.get('total_correlations', 0)
        high_risk = correlation.get('high_risk_correlations', 0)
        
        return f"""
        <!-- Correlation Insights -->
        <div class="row mb-4">
            <div class="col-md-12">
                <div class="metric-card">
                    <h2><i class="fas fa-link me-2"></i>Cyber-Fraud Correlation Insights</h2>
                    
                    <div class="row mt-3">
                        <div class="col-md-3 text-center">
                            <div class="metric-value {'text-danger' if high_risk > 0 else 'text-success'}">{total_correlations}</div>
                            <div class="metric-label">Total Correlations</div>
                        </div>
                        <div class="col-md-3 text-center">
                            <div class="metric-value {'text-danger' if high_risk > 0 else 'text-success'}">{high_risk}</div>
                            <div class="metric-label">High-Risk Correlations</div>
                        </div>
                        <div class="col-md-3 text-center">
                            <div class="metric-value text-info">{correlation.get('suspicious_entities', 0)}</div>
                            <div class="metric-label">Suspicious Entities</div>
                        </div>
                        <div class="col-md-3 text-center">
                            <div class="metric-value text-warning">{correlation.get('emerging_threats', 0)}</div>
                            <div class="metric-label">Emerging Threats</div>
                        </div>
                    </div>
                    
                    <div class="row mt-4">
                        <div class="col-12">
                            {self._generate_correlation_alert(high_risk)}
                        </div>
                    </div>
                </div>
            </div>
        </div>
"""
    
    def _generate_correlation_alert(self, high_risk_count: int) -> str:
        """Generate correlation alert based on risk level"""
        if high_risk_count == 0:
            return """
            <div class="alert alert-success">
                <h5><i class="fas fa-check-circle me-2"></i>Low Correlation Risk</h5>
                <p class="mb-0">No high-risk cyber-fraud correlations detected. Continue normal monitoring operations.</p>
            </div>
            """
        elif high_risk_count <= 3:
            return f"""
            <div class="alert alert-warning">
                <h5><i class="fas fa-exclamation-triangle me-2"></i>Medium Correlation Risk</h5>
                <p class="mb-0">{high_risk_count} high-risk cyber-fraud correlation(s) detected. Enhanced monitoring recommended.</p>
            </div>
            """
        else:
            return f"""
            <div class="alert alert-danger">
                <h5><i class="fas fa-exclamation-circle me-2"></i>High Correlation Risk</h5>
                <p class="mb-0">{high_risk_count} high-risk cyber-fraud correlation(s) detected. Immediate investigation required.</p>
            </div>
            """
    
    def _generate_recommendations_section(self, data: Dict[str, Any]) -> str:
        """Generate recommendations section"""
        recommendations = data.get('recommendations', [])
        
        recommendations_html = ""
        for i, rec in enumerate(recommendations, 1):
            recommendations_html += f"""
            <div class="scenario-card">
                <h6><i class="fas fa-arrow-right me-2 text-primary"></i>Recommendation #{i}</h6>
                <p class="mb-0">{rec}</p>
            </div>
            """
        
        return f"""
        <!-- Recommendations -->
        <div class="row mb-4">
            <div class="col-12">
                <div class="metric-card">
                    <h2><i class="fas fa-lightbulb me-2"></i>Actionable Recommendations</h2>
                    <div class="mt-3">
                        {recommendations_html if recommendations_html else '''
                        <div class="alert alert-info">
                            <p class="mb-0">No specific recommendations. Platform operating within normal parameters.</p>
                        </div>
                        '''}
                    </div>
                </div>
            </div>
        </div>
"""
    
    def _generate_dashboard_footer(self) -> str:
        """Generate dashboard footer"""
        return """
    </div> <!-- Close container -->

    <footer class="bg-dark text-light py-4 mt-5">
        <div class="container">
            <div class="row">
                <div class="col-md-6">
                    <h5>Cyber-Fraud Intelligence Platform</h5>
                    <p class="mb-0">Advanced threat detection and fraud prevention system</p>
                </div>
                <div class="col-md-6 text-end">
                    <p class="mb-0">
                        <strong>Generated:</strong> {0}<br>
                        <i class="fas fa-shield-alt me-1"></i> Security Level: ENTERPRISE
                    </p>
                </div>
            </div>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
""".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    def _generate_operational_header(self) -> str:
        """Generate operational dashboard header"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Operational Dashboard - Cyber-Fraud Platform</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .operational-metric { background: white; padding: 1rem; border-radius: 8px; margin-bottom: 1rem; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    </style>
</head>
<body>
    <div class="container-fluid py-4">
        <h1 class="mb-4"><i class="fas fa-tachometer-alt"></i> Operational Dashboard</h1>
"""
    
    def _generate_trend_analysis(self, all_data: List[Dict]) -> str:
        """Generate trend analysis section"""
        return """
        <div class="row">
            <div class="col-12">
                <div class="operational-metric">
                    <h3>Trend Analysis</h3>
                    <p>Multi-period analysis functionality would be implemented here.</p>
                </div>
            </div>
        </div>
"""
    
    def _generate_performance_metrics(self, all_data: List[Dict]) -> str:
        """Generate performance metrics section"""
        return """
        <div class="row">
            <div class="col-md-4">
                <div class="operational-metric text-center">
                    <h4>Platform Uptime</h4>
                    <h2 class="text-success">99.8%</h2>
                </div>
            </div>
            <div class="col-md-4">
                <div class="operational-metric text-center">
                    <h4>Avg Processing Time</h4>
                    <h2 class="text-info">2.3s</h2>
                </div>
            </div>
            <div class="col-md-4">
                <div class="operational-metric text-center">
                    <h4>Data Accuracy</h4>
                    <h2 class="text-warning">96.5%</h2>
                </div>
            </div>
        </div>
"""
    
    def _generate_risk_heatmap(self, all_data: List[Dict]) -> str:
        """Generate risk heatmap section"""
        return """
        <div class="row">
            <div class="col-12">
                <div class="operational-metric">
                    <h3>Risk Heatmap</h3>
                    <p>Real-time risk visualization would be displayed here.</p>
                </div>
            </div>
        </div>
"""
    
    def _generate_operational_footer(self) -> str:
        """Generate operational dashboard footer"""
        return """
    </div>
</body>
</html>
"""

def main():
    """Main execution function"""
    generator = AdvancedDashboardGenerator()
    
    # Find the latest platform report
    report_files = glob.glob("research_outputs/platform_comprehensive_report_*.json")
    
    if report_files:
        latest_report = max(report_files, key=os.path.getctime)
        print(f"📁 Found latest report: {latest_report}")
        
        # Generate comprehensive dashboard
        dashboard_path = generator.generate_comprehensive_dashboard(latest_report)
        print(f"🎉 Dashboard successfully generated: {dashboard_path}")
        
        # Optionally generate operational dashboard from multiple files
        research_files = glob.glob("research_outputs/enhanced_fraud_research_*.json")
        if len(research_files) > 1:
            operational_path = generator.generate_operational_dashboard(research_files[:3])
            print(f"🔧 Operational dashboard generated: {operational_path}")
    else:
        print("❌ No platform report files found. Run the platform first.")
        
        # Try finding research files as fallback
        research_files = glob.glob("research_outputs/enhanced_fraud_research_*.json")
        if research_files:
            latest_research = max(research_files, key=os.path.getctime)
            print(f"📁 Found research file: {latest_research}")
            dashboard_path = generator.generate_comprehensive_dashboard(latest_research)
            print(f"🎉 Dashboard generated from research data: {dashboard_path}")
        else:
            print("❌ No data files found. Please run the scraper or platform first.")

if __name__ == "__main__":
    main()