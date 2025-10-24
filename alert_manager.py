import json
import smtplib
import requests
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from datetime import datetime
from typing import Dict, List, Any, Optional

class TelegramNotifier:
    """Handles Telegram notifications for alerts"""
    
    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.base_url = f"https://api.telegram.org/bot{bot_token}"
    
    def send_message(self, message: str, parse_mode: str = 'HTML') -> bool:
        """Send message to Telegram channel/group"""
        url = f"{self.base_url}/sendMessage"
        payload = {
            'chat_id': self.chat_id,
            'text': message,
            'parse_mode': parse_mode
        }
        
        try:
            response = requests.post(url, json=payload, timeout=10)
            if response.status_code == 200:
                print("✅ Telegram message sent successfully")
                return True
            else:
                print(f"❌ Telegram error: {response.text}")
                return False
        except Exception as e:
            print(f"❌ Telegram connection error: {e}")
            return False
    
    def send_document(self, file_path: str, caption: str = "") -> bool:
        """Send file/document to Telegram"""
        url = f"{self.base_url}/sendDocument"
        
        try:
            with open(file_path, 'rb') as file:
                files = {'document': file}
                data = {'chat_id': self.chat_id, 'caption': caption}
                response = requests.post(url, files=files, data=data, timeout=30)
                
            if response.status_code == 200:
                print("✅ Telegram file sent successfully")
                return True
            else:
                print(f"❌ Telegram file error: {response.text}")
                return False
        except Exception as e:
            print(f"❌ Telegram file upload error: {e}")
            return False

class UnifiedAlertManager:
    """Comprehensive alert manager for fraud, sanctions, and correlation alerts"""
    
    def __init__(self, config_file: str = 'alert_config.json'):
        self.config = self._load_config(config_file)
        self.telegram = None
        
        if self.config['telegram']['enabled']:
            self.telegram = TelegramNotifier(
                self.config['telegram']['bot_token'],
                self.config['telegram']['chat_id']
            )
    
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Load alert configuration from JSON file"""
        default_config = {
            'email': {
                'enabled': False,
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'sender_email': '',
                'sender_password': '',
                'recipients': []
            },
            'telegram': {
                'enabled': False,
                'bot_token': '',
                'chat_id': ''
            },
            'high_risk_threshold': 0.7,
            'clari5_integration': {
                'enabled': False,
                'base_url': '',
                'auth_token': ''
            }
        }
        
        try:
            with open(config_file, 'r') as f:
                user_config = json.load(f)
                # Deep merge configuration
                self._deep_merge(default_config, user_config)
        except FileNotFoundError:
            print(f"⚠️  Alert config not found at {config_file}. Using defaults.")
        
        return default_config
    
    def _deep_merge(self, default: Dict, user: Dict) -> None:
        """Recursively merge user configuration into default"""
        for key, value in user.items():
            if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                self._deep_merge(default[key], value)
            else:
                default[key] = value
    
    def send_comprehensive_alert(self, alert_type: str, data: Dict[str, Any], 
                               attachments: Optional[List[str]] = None) -> None:
        """
        Send comprehensive alerts via all configured channels
        
        Args:
            alert_type: Type of alert ('fraud', 'sanction', 'correlation', 'platform_daily_report', 'platform_error')
            data: Alert data specific to the alert type
            attachments: List of file paths to attach
        """
        print(f"🔔 Sending {alert_type.upper()} alerts...")
        
        # Telegram alerts
        if self.telegram:
            message = self._format_telegram_message(alert_type, data)
            if message:
                self.telegram.send_message(message)
            
            # Send attachments
            if attachments:
                for attachment in attachments:
                    if os.path.exists(attachment):
                        self.telegram.send_document(attachment, f"{alert_type} report")
        
        # Email alerts
        if self.config['email']['enabled']:
            self._send_detailed_email(alert_type, data, attachments)
        
        print(f"✅ {alert_type.title()} alerts processed")
    
    def _format_telegram_message(self, alert_type: str, data: Dict[str, Any]) -> str:
        """Format message based on alert type for Telegram"""
        formatters = {
            'fraud': self._format_fraud_telegram,
            'sanction': self._format_sanction_telegram,
            'correlation': self._format_correlation_telegram,
            'platform_daily_report': self._format_platform_daily_report_telegram,
            'platform_error': self._format_platform_error_telegram
        }
        
        formatter = formatters.get(alert_type)
        return formatter(data) if formatter else None
    
    def _format_fraud_telegram(self, data: Dict[str, Any]) -> str:
        """Format fraud detection alert for Telegram"""
        return f"""
🚨 <b>FRAUD PATTERN DETECTED</b>
⏰ <i>{datetime.now().strftime('%Y-%m-%d %H:%M')}</i>

📊 <b>Summary:</b>
• Patterns Detected: {data.get('patterns_detected', 0)}
• Scenarios Generated: {data.get('scenarios_generated', 0)}
• High-Confidence: {data.get('high_confidence', 0)}

🔍 <b>Top Patterns:</b>
{self._format_patterns_list(data.get('pattern_breakdown', {}))}

⚠️ <b>Action Required:</b> Review in Clari5 Case Management
"""
    
    def _format_sanction_telegram(self, data: Dict[str, Any]) -> str:
        """Format sanction screening alert for Telegram"""
        return f"""
🚫 <b>SANCTION SCREENING ALERT</b>
⏰ <i>{datetime.now().strftime('%Y-%m-%d %H:%M')}</i>

👤 <b>Customer:</b> {data.get('customer_name', 'Unknown')}
📋 <b>ID:</b> {data.get('customer_id', 'N/A')}
🎯 <b>Screening Type:</b> {data.get('screening_type', 'Unknown')}

🔍 <b>Matches Found:</b> {len(data.get('matches', []))}
📊 <b>Highest Score:</b> {data.get('highest_match_score', 0):.2f}

<b>Top Matches:</b>
{self._format_matches_list(data.get('matches', []))}

⚠️ <b>Action Required:</b> Immediate review required
"""
    
    def _format_correlation_telegram(self, data: Dict[str, Any]) -> str:
        """Format cyber-fraud correlation alert for Telegram"""
        return f"""
🔗 <b>CYBER-FRAUD CORRELATION</b>
⏰ <i>{datetime.now().strftime('%Y-%m-%d %H:%M')}</i>

🔄 <b>Correlation Type:</b> {data.get('correlation_type', 'Unknown')}
📊 <b>Confidence:</b> {data.get('confidence_score', 0):.2f}

👤 <b>Customer:</b> {data.get('customer_email', 'Unknown')}
💻 <b>Cyber Event:</b> {data.get('cyber_event', 'Unknown')}
💸 <b>Fraud Event:</b> {data.get('fraud_event', 'Unknown')}

📈 <b>Risk Factors:</b>
{self._format_risk_factors(data.get('risk_factors', []))}

🎯 <b>Recommendation:</b> {data.get('recommendation', 'Immediate review required')}
"""
    
    def _format_platform_daily_report_telegram(self, data: Dict[str, Any]) -> str:
        """Format platform daily report for Telegram"""
        return f"""
📊 <b>PLATFORM DAILY REPORT</b>
⏰ <i>{datetime.now().strftime('%Y-%m-%d %H:%M')}</i>

📈 <b>Daily Operations Summary:</b>
• Threat Intel Items: {data.get('threat_intel_items', 0)}
• Fraud Patterns: {data.get('fraud_patterns', 0)}
• High Risk Findings: {data.get('high_risk_findings', 0)}
• Cyber-Fraud Correlations: {data.get('cyber_fraud_correlations', 0)}

📁 <b>Report File:</b> {data.get('report_file', 'N/A')}

✅ <b>Status:</b> Daily operations completed successfully
"""

    def _format_platform_error_telegram(self, data: Dict[str, Any]) -> str:
        """Format platform error alert for Telegram"""
        return f"""
❌ <b>PLATFORM ERROR</b>
⏰ <i>{datetime.now().strftime('%Y-%m-%d %H:%M')}</i>

🛑 <b>Error Details:</b>
{data.get('error', 'Unknown error')}

🚨 <b>Action Required:</b> Immediate technical review needed
"""
    
    def _format_patterns_list(self, patterns: Dict[str, int]) -> str:
        """Format patterns for Telegram message"""
        if not patterns:
            return "• No patterns detected"
        
        return "\n".join([f"• {pattern}: {count}" for pattern, count in list(patterns.items())[:5]])
    
    def _format_matches_list(self, matches: List[Dict]) -> str:
        """Format matches for Telegram message"""
        if not matches:
            return "• No matches found"
        
        formatted = []
        for i, match in enumerate(matches[:3], 1):
            formatted.append(f"{i}. {match['sanction_entity']['list_source']}: {match['match_score']:.2f}")
        return "\n".join(formatted)
    
    def _format_risk_factors(self, risk_factors: List[str]) -> str:
        """Format risk factors for Telegram message"""
        if not risk_factors:
            return "• No specific risk factors"
        
        return "\n".join([f"• {factor}" for factor in risk_factors[:5]])
    
    def _send_detailed_email(self, alert_type: str, data: Dict[str, Any], 
                           attachments: Optional[List[str]] = None) -> None:
        """Send detailed email with HTML formatting and attachments"""
        try:
            msg = MIMEMultipart()
            msg['Subject'] = self._get_email_subject(alert_type)
            msg['From'] = self.config['email']['sender_email']
            msg['To'] = ', '.join(self.config['email']['recipients'])
            
            # Create email body
            html_content = self._generate_email_content(alert_type, data)
            msg.attach(MIMEText(html_content, 'html'))
            
            # Attach files
            if attachments:
                for file_path in attachments:
                    if os.path.exists(file_path):
                        self._attach_file(msg, file_path)
            
            # Send email
            self._send_via_smtp(msg)
            
        except Exception as e:
            print(f"❌ Email error: {e}")
    
    def _get_email_subject(self, alert_type: str) -> str:
        """Generate email subject based on alert type"""
        subjects = {
            'fraud': f"🚨 Fraud Pattern Detection Alert - {datetime.now().strftime('%Y-%m-%d')}",
            'sanction': f"🚫 Sanction Screening Alert - {datetime.now().strftime('%Y-%m-%d')}",
            'correlation': f"🔗 Cyber-Fraud Correlation Alert - {datetime.now().strftime('%Y-%m-%d')}",
            'platform_daily_report': f"📊 Platform Daily Report - {datetime.now().strftime('%Y-%m-%d')}",
            'platform_error': f"❌ Platform Error Alert - {datetime.now().strftime('%Y-%m-%d')}"
        }
        return subjects.get(alert_type, "Security Alert")
    
    def _generate_email_content(self, alert_type: str, data: Dict[str, Any]) -> str:
        """Generate HTML email content based on alert type"""
        templates = {
            'fraud': self._generate_fraud_email,
            'sanction': self._generate_sanction_email,
            'correlation': self._generate_correlation_email,
            'platform_daily_report': self._generate_platform_daily_report_email,
            'platform_error': self._generate_platform_error_email
        }
        
        generator = templates.get(alert_type, self._generate_generic_email)
        return generator(data)
    
    def _generate_fraud_email(self, data: Dict[str, Any]) -> str:
        """Generate fraud detection email content"""
        return f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #e74c3c; color: white; padding: 20px; }}
                .summary {{ background: #f9ebea; padding: 15px; margin: 10px 0; }}
                .pattern {{ background: #3498db; color: white; padding: 5px 10px; margin: 2px; border-radius: 3px; display: inline-block; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🚨 Fraud Pattern Detection Alert</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="summary">
                <h2>Executive Summary</h2>
                <p><strong>Patterns Detected:</strong> {data.get('patterns_detected', 0)}</p>
                <p><strong>Scenarios Generated:</strong> {data.get('scenarios_generated', 0)}</p>
                <p><strong>High-Confidence Findings:</strong> {data.get('high_confidence', 0)}</p>
            </div>
            
            <h2>Pattern Distribution</h2>
            {self._generate_patterns_html(data.get('pattern_breakdown', {}))}
            
            <hr>
            <p><em>This alert was automatically generated by the Cyber-Fraud Intelligence Platform.</em></p>
        </body>
        </html>
        """
    
    def _generate_sanction_email(self, data: Dict[str, Any]) -> str:
        """Generate sanction screening email content"""
        return f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #e67e22; color: white; padding: 20px; }}
                .summary {{ background: #fef5e7; padding: 15px; margin: 10px 0; }}
                .match {{ background: #f39c12; color: white; padding: 5px 10px; margin: 2px; border-radius: 3px; display: inline-block; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🚫 Sanction Screening Alert</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="summary">
                <h2>Executive Summary</h2>
                <p><strong>Customer:</strong> {data.get('customer_name', 'Unknown')}</p>
                <p><strong>Customer ID:</strong> {data.get('customer_id', 'N/A')}</p>
                <p><strong>Screening Type:</strong> {data.get('screening_type', 'Unknown')}</p>
                <p><strong>Matches Found:</strong> {len(data.get('matches', []))}</p>
                <p><strong>Highest Match Score:</strong> {data.get('highest_match_score', 0):.2f}</p>
            </div>
            
            <h2>Top Matches</h2>
            {self._generate_matches_html(data.get('matches', []))}
            
            <hr>
            <p><em>This alert was automatically generated by the Cyber-Fraud Intelligence Platform.</em></p>
        </body>
        </html>
        """
    
    def _generate_correlation_email(self, data: Dict[str, Any]) -> str:
        """Generate correlation alert email content"""
        return f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #9b59b6; color: white; padding: 20px; }}
                .summary {{ background: #f4ecf7; padding: 15px; margin: 10px 0; }}
                .risk-factor {{ background: #8e44ad; color: white; padding: 5px 10px; margin: 2px; border-radius: 3px; display: inline-block; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔗 Cyber-Fraud Correlation Alert</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="summary">
                <h2>Executive Summary</h2>
                <p><strong>Correlation Type:</strong> {data.get('correlation_type', 'Unknown')}</p>
                <p><strong>Confidence Score:</strong> {data.get('confidence_score', 0):.2f}</p>
                <p><strong>Customer:</strong> {data.get('customer_email', 'Unknown')}</p>
                <p><strong>Cyber Event:</strong> {data.get('cyber_event', 'Unknown')}</p>
                <p><strong>Fraud Event:</strong> {data.get('fraud_event', 'Unknown')}</p>
            </div>
            
            <h2>Risk Factors</h2>
            {self._generate_risk_factors_html(data.get('risk_factors', []))}
            
            <h2>Recommendation</h2>
            <p>{data.get('recommendation', 'Immediate review required')}</p>
            
            <hr>
            <p><em>This alert was automatically generated by the Cyber-Fraud Intelligence Platform.</em></p>
        </body>
        </html>
        """
    
    def _generate_platform_daily_report_email(self, data: Dict[str, Any]) -> str:
        """Generate platform daily report email content"""
        return f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; }}
                .summary {{ background: #ecf0f1; padding: 15px; margin: 10px 0; }}
                .metric {{ background: #34495e; color: white; padding: 10px; margin: 5px; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>📊 Platform Daily Report</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="summary">
                <h2>Executive Summary</h2>
                <div class="metric">
                    <p><strong>Threat Intel Items:</strong> {data.get('threat_intel_items', 0)}</p>
                </div>
                <div class="metric">
                    <p><strong>Fraud Patterns:</strong> {data.get('fraud_patterns', 0)}</p>
                </div>
                <div class="metric">
                    <p><strong>High Risk Findings:</strong> {data.get('high_risk_findings', 0)}</p>
                </div>
                <div class="metric">
                    <p><strong>Cyber-Fraud Correlations:</strong> {data.get('cyber_fraud_correlations', 0)}</p>
                </div>
            </div>
            
            <h2>Report File</h2>
            <p>{data.get('report_file', 'N/A')}</p>
            
            <hr>
            <p><em>This report was automatically generated by the Cyber-Fraud Intelligence Platform.</em></p>
        </body>
        </html>
        """
    
    def _generate_platform_error_email(self, data: Dict[str, Any]) -> str:
        """Generate platform error email content"""
        return f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #c0392b; color: white; padding: 20px; }}
                .error {{ background: #fadbd8; padding: 15px; margin: 10px 0; border-left: 5px solid #e74c3c; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>❌ Platform Error Alert</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="error">
                <h2>Error Details</h2>
                <p><strong>Error Message:</strong> {data.get('error', 'Unknown error')}</p>
                <p><strong>Timestamp:</strong> {data.get('timestamp', 'N/A')}</p>
            </div>
            
            <h2>Required Action</h2>
            <p>Immediate technical review and resolution required.</p>
            
            <hr>
            <p><em>This alert was automatically generated by the Cyber-Fraud Intelligence Platform.</em></p>
        </body>
        </html>
        """
    
    def _generate_generic_email(self, data: Dict[str, Any]) -> str:
        """Generate generic email content for unhandled alert types"""
        return f"""
        <html>
        <body>
            <h1>Security Alert</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <pre>{json.dumps(data, indent=2)}</pre>
        </body>
        </html>
        """
    
    def _generate_patterns_html(self, patterns: Dict[str, int]) -> str:
        """Generate HTML for patterns display"""
        if not patterns:
            return "<p>No patterns detected</p>"
        
        html = ""
        for pattern, count in patterns.items():
            html += f'<span class="pattern">{pattern}: {count}</span> '
        return html
    
    def _generate_matches_html(self, matches: List[Dict]) -> str:
        """Generate HTML for matches display"""
        if not matches:
            return "<p>No matches found</p>"
        
        html = "<ul>"
        for match in matches[:5]:
            entity = match['sanction_entity']
            html += f"<li>{entity['list_source']}: {match['match_score']:.2f} - {entity['name']}</li>"
        html += "</ul>"
        return html
    
    def _generate_risk_factors_html(self, risk_factors: List[str]) -> str:
        """Generate HTML for risk factors display"""
        if not risk_factors:
            return "<p>No specific risk factors</p>"
        
        html = "<ul>"
        for factor in risk_factors:
            html += f"<li>{factor}</li>"
        html += "</ul>"
        return html
    
    def _attach_file(self, msg: MIMEMultipart, file_path: str) -> None:
        """Attach file to email"""
        try:
            with open(file_path, 'rb') as file:
                part = MIMEApplication(file.read(), Name=os.path.basename(file_path))
                part['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
                msg.attach(part)
        except Exception as e:
            print(f"❌ Failed to attach {file_path}: {e}")
    
    def _send_via_smtp(self, msg: MIMEMultipart) -> None:
        """Send email via SMTP server"""
        try:
            with smtplib.SMTP(self.config['email']['smtp_server'], 
                            self.config['email']['smtp_port']) as server:
                server.starttls()
                server.login(self.config['email']['sender_email'],
                           self.config['email']['sender_password'])
                server.send_message(msg)
            
            print("✅ Email sent successfully")
        except Exception as e:
            print(f"❌ SMTP error: {e}")

def create_alert_config() -> None:
    """Create a default alert configuration file"""
    config = {
        "email": {
            "enabled": True,
            "smtp_server": "smtp.gmail.com",
            "smtp_port": 587,
            "sender_email": "your-email@gmail.com",
            "sender_password": "your-app-password",
            "recipients": ["security-team@company.com"]
        },
        "telegram": {
            "enabled": True,
            "bot_token": "YOUR_BOT_TOKEN_HERE",
            "chat_id": "YOUR_CHAT_ID_HERE"
        },
        "high_risk_threshold": 0.7,
        "clari5_integration": {
            "enabled": False,
            "base_url": "https://your-clari5-instance/api",
            "auth_token": "your-auth-token"
        }
    }
    
    with open('alert_config.json', 'w') as f:
        json.dump(config, f, indent=2)
    
    print("✅ Created alert_config.json - please update with your actual settings")

if __name__ == "__main__":
    create_alert_config()