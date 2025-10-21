import requests
from bs4 import BeautifulSoup
import json
import re
import time
from datetime import datetime
import feedparser  # For RSS feeds

class FraudPatternScraper:
    def __init__(self):
        self.sources = {
            'krebs_rss': 'https://krebsonsecurity.com/feed/',
            'threatpost_rss': 'https://threatpost.com/feed/',
            'cisa_rss': 'https://www.cisa.gov/news-events/cybersecurity-advisories',
            'nvd': 'https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=banking&search_type=all'
        }
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def scrape_via_rss(self, url, source_name):
        """Scrape using RSS feeds for more reliable data"""
        try:
            feed = feedparser.parse(url)
            articles = []
            
            for entry in feed.entries[:8]:  # Get latest 8 entries
                # Get full content if available
                content = ''
                if hasattr(entry, 'summary'):
                    content = entry.summary
                elif hasattr(entry, 'description'):
                    content = entry.description
                
                articles.append({
                    'title': entry.title,
                    'url': entry.link,
                    'content': f"{entry.title}. {content}",
                    'source': source_name,
                    'timestamp': datetime.now().isoformat(),
                    'published': entry.get('published', '')
                })
            
            return articles
        except Exception as e:
            print(f"Error scraping {source_name} RSS: {e}")
            return []

    def scrape_krebs(self):
        """Scrape Krebs via RSS for better content"""
        return self.scrape_via_rss(self.sources['krebs_rss'], 'KrebsOnSecurity')

    def scrape_threatpost(self):
        """Scrape ThreatPost via RSS"""
        return self.scrape_via_rss(self.sources['threatpost_rss'], 'ThreatPost')

    def scrape_cisa_alerts(self):
        """Scrape CISA via RSS"""
        return self.scrape_via_rss(self.sources['cisa_rss'], 'CISA')

    def search_cves(self, keywords=['banking', 'financial', 'payment', 'pos', 'atm', 'card']):
        """Search for CVEs using NVD API"""
        print("Searching for financial-related CVEs via NVD...")
        cves = []
        
        for keyword in keywords[:4]:  # Limit to avoid rate limiting
            try:
                # NVD REST API
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}"
                response = self.session.get(url, timeout=15)
                
                if response.status_code == 200:
                    data = response.json()
                    vulnerabilities = data.get('vulnerabilities', [])
                    
                    for vuln in vulnerabilities[:3]:  # Get top 3 per keyword
                        cve_data = vuln['cve']
                        description = cve_data['descriptions'][0]['value']
                        
                        # Only include if it's relevant to financial systems
                        if any(fin_keyword in description.lower() for fin_keyword in ['bank', 'payment', 'financial', 'transaction', 'card']):
                            cves.append({
                                'id': cve_data['id'],
                                'title': f"{cve_data['id']} - {keyword}",
                                'content': description,
                                'source': 'NVD CVE Database',
                                'timestamp': datetime.now().isoformat(),
                                'score': cve_data.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', 'N/A')
                            })
                
                time.sleep(2)  # Respect rate limits
                
            except Exception as e:
                print(f"Error searching CVE for {keyword}: {e}")
                continue
        
        return cves

 
    def scrape_reddit_threat_intel(self):
     """Alternative Reddit scraping using specific threat intel subreddits"""
     print("Checking Reddit threat intelligence...")
     try:
        # Try multiple subreddits known for threat intelligence
        subreddits = [
            'https://www.reddit.com/r/cybersecurity/top/.json?limit=5',
            'https://www.reddit.com/r/netsec/top/.json?limit=5',
            'https://www.reddit.com/r/blueteam/top/.json?limit=5'
        ]
        
        posts = []
        for subreddit_url in subreddits:
            try:
                response = self.session.get(subreddit_url, timeout=15, 
                                          headers={'User-Agent': 'FraudResearchBot/1.0'})
                if response.status_code == 200:
                    data = response.json()
                    for post in data['data']['children'][:3]:  # Get top 3 posts
                        post_data = post['data']
                        # Filter for relevant content
                        title = post_data.get('title', '')
                        if any(keyword in title.lower() for keyword in ['malware', 'phishing', 'fraud', 'bank', 'financial']):
                            posts.append({
                                'title': title,
                                'url': f"https://reddit.com{post_data.get('permalink', '')}",
                                'content': f"{title}. {post_data.get('selftext', '')}",
                                'source': 'Reddit Threat Intel',
                                'timestamp': datetime.now().isoformat(),
                                'upvotes': post_data.get('ups', 0)
                            })
                time.sleep(1)  # Be respectful
            except Exception as e:
                print(f"  Error with subreddit {subreddit_url}: {e}")
                continue
        
        return posts
        
     except Exception as e:
        print(f"Error scraping Reddit: {e}")
        return []
    
    def scrape_all_sources(self):
        """Run all scrapers and return combined results"""
        print("Starting enhanced fraud pattern research...")
        
        all_data = []
        
        # Scrape each source with error handling
        sources = [
            ('Krebs RSS', self.scrape_krebs),
            ('CISA RSS', self.scrape_cisa_alerts),
            ('ThreatPost RSS', self.scrape_threatpost),
            ('CVE Database', self.search_cves),
            ('Reddit Intel', self.scrape_reddit_threat_intel)
        ]
        
        for source_name, scraper_func in sources:
            try:
                data = scraper_func()
                all_data.extend(data)
                print(f"✓ {source_name}: {len(data)} items")
            except Exception as e:
                print(f"✗ {source_name}: Failed - {e}")
        
        print(f"Scraping complete. Found {len(all_data)} items.")
        return all_data