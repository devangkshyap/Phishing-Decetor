from flask import Flask, render_template, request, jsonify, flash, redirect, url_for
import os
import re
import requests
import hashlib
import json
import base64
import ssl
import socket
import time
import threading
import subprocess
import platform
import urllib.parse
import logging
from collections import defaultdict
from datetime import datetime
from urllib.parse import urlparse, urljoin
from werkzeug.utils import secure_filename

# Optional imports with fallbacks
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    print("Warning: python-magic not available. File type detection will be limited.")

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print("Warning: dnspython not available. DNS analysis will be disabled.")

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("Warning: python-whois not available. WHOIS analysis will be disabled.")

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    print("Warning: beautifulsoup4 not available. Web content analysis will be limited.")

try:
    import ipaddress
    IPADDRESS_AVAILABLE = True
except ImportError:
    IPADDRESS_AVAILABLE = False
    print("Warning: ipaddress not available. IP analysis will be limited.")

try:
    from dotenv import load_dotenv
    load_dotenv()
    DOTENV_AVAILABLE = True
except ImportError:
    DOTENV_AVAILABLE = False
    print("Warning: python-dotenv not available. Environment variables from .env will not be loaded.")

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.firefox.options import Options as FirefoxOptions
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from webdriver_manager.chrome import ChromeDriverManager
    from webdriver_manager.firefox import GeckoDriverManager
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.firefox.service import Service as FirefoxService
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    print("Warning: selenium not available. Screenshot functionality will be disabled.")

try:
    from PIL import Image, ImageDraw
    import io
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print("Warning: Pillow not available. Image processing will be disabled.")

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from io import BytesIO
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    print("Warning: reportlab not available. PDF generation will be disabled.")

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# API Configuration - Add your API keys here
API_CONFIG = {
    # VirusTotal API (Free tier: 4 requests/minute)
    'VIRUSTOTAL_API_KEY': os.getenv('VIRUSTOTAL_API_KEY', ''),
    
    # URLVoid API (Free tier: 1000 requests/month)
    'URLVOID_API_KEY': os.getenv('URLVOID_API_KEY', ''),
    
    # PhishTank API (Free)
    'PHISHTANK_API_KEY': os.getenv('PHISHTANK_API_KEY', ''),
    
    # Google Safe Browsing API (Free tier: 10,000 requests/day)
    'GOOGLE_SAFE_BROWSING_API_KEY': os.getenv('GOOGLE_SAFE_BROWSING_API_KEY', ''),
    
    # AbuseIPDB API (Free tier: 1000 checks/day)
    'ABUSEIPDB_API_KEY': os.getenv('ABUSEIPDB_API_KEY', ''),
    
    # Shodan API (Free account: 100 queries/month)
    'SHODAN_API_KEY': os.getenv('SHODAN_API_KEY', ''),
    
    # IPQualityScore API (Free tier: 5000 lookups/month)
    'IPQUALITYSCORE_API_KEY': os.getenv('IPQUALITYSCORE_API_KEY', ''),
    
    # Have I Been Pwned API (Free for breach checking)
    'HIBP_API_KEY': os.getenv('HIBP_API_KEY', ''),
}

# Suspicious keywords for phishing detection
PHISHING_KEYWORDS = [
    'urgent', 'verify', 'suspend', 'limited time', 'click here', 'update payment',
    'confirm identity', 'security alert', 'account locked', 'winner', 'congratulations',
    'free money', 'act now', 'expire', 'validate', 'login immediately'
]

SUSPICIOUS_DOMAINS = [
    'bit.ly', 'tinyurl.com', 'short.link', 'ow.ly', 'buff.ly'
]

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'mp4', 'avi', 'mov'}

# Threat intelligence cache
threat_cache = defaultdict(dict)
cache_expiry = 3600  # 1 hour

# Rate limiting
request_counts = defaultdict(list)
rate_limit_window = 300  # 5 minutes
max_requests_per_window = 100

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def rate_limit_check(client_ip):
    """Check if client has exceeded rate limit"""
    current_time = int(time.time())
    window_start = current_time - rate_limit_window
    
    # Clean old entries for this IP
    if client_ip in request_counts:
        request_counts[client_ip] = [timestamp for timestamp in request_counts[client_ip] if timestamp > window_start]
    
    # Check current IP
    if len(request_counts[client_ip]) >= max_requests_per_window:
        return False
    
    request_counts[client_ip].append(current_time)
    return True

def create_placeholder_screenshot(url, width=800, height=600):
    """Create a placeholder screenshot when browser automation fails"""
    try:
        # Create a new image with white background
        image = Image.new('RGB', (width, height), color='white')
        draw = ImageDraw.Draw(image)
        
        # Try to use a default font, fall back to basic if not available
        try:
            from PIL import ImageFont
            font = ImageFont.truetype("arial.ttf", 24)
            small_font = ImageFont.truetype("arial.ttf", 16)
        except:
            font = ImageFont.load_default()
            small_font = ImageFont.load_default()
        
        # Draw placeholder content
        draw.rectangle([(50, 50), (width-50, 100)], fill='#f0f0f0', outline='#ccc')
        draw.text((60, 65), "Screenshot Preview", fill='black', font=font)
        
        draw.rectangle([(50, 120), (width-50, height-120)], fill='#fafafa', outline='#ddd')
        draw.text((60, 140), f"URL: {url}", fill='#666', font=small_font)
        draw.text((60, 170), "Screenshot capture temporarily unavailable", fill='#666', font=small_font)
        draw.text((60, 190), "Browser automation is being configured...", fill='#666', font=small_font)
        
        # Add some visual elements
        draw.rectangle([(60, 220), (width-60, 240)], fill='#e0e0e0')
        draw.rectangle([(60, 260), (width-60, 280)], fill='#e0e0e0')
        draw.rectangle([(60, 300), (width-200, 320)], fill='#e0e0e0')
        
        # Convert to base64
        img_buffer = io.BytesIO()
        image.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        
        import base64
        screenshot_base64 = base64.b64encode(img_buffer.getvalue()).decode('utf-8')
        
        return {
            'success': True,
            'screenshot_data': f"data:image/png;base64,{screenshot_base64}",
            'screenshot_size': len(screenshot_base64),
            'dimensions': f"{image.width}x{image.height}",
            'original_url': url,
            'final_url': url,
            'is_placeholder': True
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': f'Failed to create placeholder screenshot: {str(e)}',
            'screenshot_data': None
        }

def capture_webpage_screenshot(url, timeout=15):
    """Capture a screenshot of a webpage safely"""
    if not SELENIUM_AVAILABLE:
        return {
            'success': False,
            'error': 'Screenshot functionality not available - selenium not installed',
            'screenshot_data': None
        }
    
    if not PIL_AVAILABLE:
        return {
            'success': False,
            'error': 'Image processing not available - Pillow not installed',
            'screenshot_data': None
        }
    
    driver = None
    try:
        # Chrome options for headless browsing with better Windows compatibility
        chrome_options = Options()
        chrome_options.add_argument('--headless=new')  # Use new headless mode
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--disable-software-rasterizer')
        chrome_options.add_argument('--window-size=1920,1080')
        chrome_options.add_argument('--disable-web-security')
        chrome_options.add_argument('--disable-features=VizDisplayCompositor')
        chrome_options.add_argument('--disable-extensions')
        chrome_options.add_argument('--disable-plugins')
        chrome_options.add_argument('--disable-default-apps')
        chrome_options.add_argument('--disable-sync')
        chrome_options.add_argument('--no-first-run')
        chrome_options.add_argument('--disable-background-timer-throttling')
        chrome_options.add_argument('--disable-renderer-backgrounding')
        chrome_options.add_argument('--disable-backgrounding-occluded-windows')
        chrome_options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
        
        # Try multiple driver setup methods for better compatibility
        driver = None
        setup_error = None
        
        # Method 1: Try with ChromeDriverManager
        try:
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=chrome_options)
        except Exception as e1:
            setup_error = str(e1)
            
            # Method 2: Try with system Chrome if available
            try:
                driver = webdriver.Chrome(options=chrome_options)
            except Exception as e2:
                # Method 3: Try Firefox as fallback
                try:
                    firefox_options = FirefoxOptions()
                    firefox_options.add_argument('--headless')
                    firefox_options.add_argument('--no-sandbox')
                    firefox_options.add_argument('--disable-dev-shm-usage')
                    firefox_options.add_argument('--window-size=1920,1080')
                    
                    firefox_service = FirefoxService(GeckoDriverManager().install())
                    driver = webdriver.Firefox(service=firefox_service, options=firefox_options)
                except Exception as e3:
                    # Method 4: Create placeholder screenshot as final fallback
                    try:
                        placeholder_result = create_placeholder_screenshot(url)
                        if placeholder_result['success']:
                            return placeholder_result
                    except:
                        pass
                    
                    return {
                        'success': False,
                        'error': f'Browser setup failed. Chrome error: {setup_error}, System Chrome error: {str(e2)}, Firefox error: {str(e3)}',
                        'screenshot_data': None
                    }
        
        if driver is None:
            return {
                'success': False,
                'error': f'Chrome WebDriver setup failed: {setup_error}',
                'screenshot_data': None
            }
        driver.set_page_load_timeout(timeout)
        
        try:
            # Navigate to the page
            driver.get(url)
            
            # Wait a moment for the page to render
            time.sleep(2)
            
            # Take screenshot
            screenshot = driver.get_screenshot_as_png()
            
            # Process screenshot with Pillow
            image = Image.open(io.BytesIO(screenshot))
            
            # Resize image for web display (maintain aspect ratio)
            max_width = 800
            max_height = 600
            image.thumbnail((max_width, max_height), Image.Resampling.LANCZOS)
            
            # Convert to base64 for web display
            img_buffer = io.BytesIO()
            image.save(img_buffer, format='PNG', optimize=True, quality=85)
            img_buffer.seek(0)
            
            import base64
            screenshot_base64 = base64.b64encode(img_buffer.getvalue()).decode('utf-8')
            
            return {
                'success': True,
                'screenshot_data': f"data:image/png;base64,{screenshot_base64}",
                'screenshot_size': len(screenshot_base64),
                'dimensions': f"{image.width}x{image.height}",
                'original_url': url,
                'final_url': driver.current_url
            }
            
        finally:
            if driver:
                try:
                    driver.quit()
                except:
                    pass
            
    except Exception as e:
        if driver:
            try:
                driver.quit()
            except:
                pass
        return {
            'success': False,
            'error': f'Screenshot capture failed: {str(e)}',
            'screenshot_data': None
        }

def get_page_content(url, timeout=10):
    """Safely fetch webpage content with improved error handling"""
    start_time = time.time()
    
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        # Use session for better connection handling
        session = requests.Session()
        session.headers.update(headers)
        
        response = session.get(
            url, 
            timeout=(5, timeout),  # (connect timeout, read timeout)
            verify=False, 
            allow_redirects=True,
            stream=False
        )
        response.raise_for_status()
        
        load_time = round(time.time() - start_time, 2)
        
        return {
            'content': response.text,
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'final_url': response.url,
            'redirect_history': [resp.url for resp in response.history],
            'load_time': f"{load_time}s"
        }
        
    except requests.exceptions.Timeout:
        return {
            'error': 'Connection timeout - The website took too long to respond',
            'content': None,
            'status_code': None,
            'timeout': True
        }
    except requests.exceptions.ConnectionError:
        return {
            'error': 'Connection failed - Unable to reach the website',
            'content': None,
            'status_code': None,
            'connection_error': True
        }
    except requests.exceptions.HTTPError as e:
        return {
            'error': f'HTTP Error {e.response.status_code}: {e.response.reason}',
            'content': None,
            'status_code': e.response.status_code,
            'http_error': True
        }
    except requests.exceptions.RequestException as e:
        return {
            'error': f'Request failed: {str(e)}',
            'content': None,
            'status_code': None,
            'request_error': True
        }
    except Exception as e:
        return {
            'error': f'Unexpected error: {str(e)}',
            'content': None,
            'status_code': None,
            'unexpected_error': True
        }

def check_ssl_certificate(domain):
    """Check SSL certificate details"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    'valid': True,
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'subject': dict(x[0] for x in cert['subject']),
                    'version': cert['version'],
                    'not_before': cert['notBefore'],
                    'not_after': cert['notAfter'],
                    'serial_number': cert['serialNumber']
                }
    except Exception as e:
        return {
            'valid': False,
            'error': str(e)
        }

def get_dns_info(domain):
    """Get comprehensive DNS information"""
    dns_info = {}
    
    if not DNS_AVAILABLE:
        dns_info['error'] = 'DNS analysis not available - dnspython not installed'
        return dns_info
    
    try:
        # A records
        a_records = dns.resolver.resolve(domain, 'A')
        dns_info['A'] = [str(record) for record in a_records]
        
        # MX records
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            dns_info['MX'] = [f"{record.preference} {record.exchange}" for record in mx_records]
        except:
            dns_info['MX'] = []
        
        # NS records
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            dns_info['NS'] = [str(record) for record in ns_records]
        except:
            dns_info['NS'] = []
            
        # TXT records
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            dns_info['TXT'] = [str(record) for record in txt_records]
        except:
            dns_info['TXT'] = []
            
    except Exception as e:
        dns_info['error'] = str(e)
    
    return dns_info

def analyze_page_content(content):
    """Analyze webpage content for suspicious elements"""
    if not content:
        return {}
    
    analysis = {
        'forms': [],
        'external_links': [],
        'suspicious_scripts': [],
        'meta_info': {},
        'suspicious_elements': []
    }
    
    try:
        # Basic content analysis without BeautifulSoup for now
        # Count forms
        form_count = content.lower().count('<form')
        analysis['forms'] = [f"Found {form_count} forms on page"]
        
        # Look for suspicious keywords in content
        suspicious_keywords = [
            'urgent', 'verify account', 'suspended', 'click here', 'winner',
            'congratulations', 'free money', 'limited time', 'act now',
            'confirm identity', 'security alert', 'update payment'
        ]
        
        content_lower = content.lower()
        found_keywords = [kw for kw in suspicious_keywords if kw in content_lower]
        if found_keywords:
            analysis['suspicious_elements'].extend([f"Suspicious keyword: {kw}" for kw in found_keywords])
        
        # Check for password fields
        password_fields = content.lower().count('type="password"')
        if password_fields > 0:
            analysis['suspicious_elements'].append(f"Found {password_fields} password fields")
        
        # Check for external scripts
        script_count = content.lower().count('<script')
        if script_count > 10:
            analysis['suspicious_scripts'].append(f"High number of scripts: {script_count}")
            
    except Exception as e:
        analysis['error'] = str(e)
    
    return analysis

class SecurityAnalyzer:
    def __init__(self):
        self.risk_score = 0
        self.warnings = []
        self.recommendations = []
        self.api_results = {}
        
    def check_virustotal(self, url):
        """Check URL against VirusTotal database"""
        if not API_CONFIG['VIRUSTOTAL_API_KEY']:
            return {'available': False, 'reason': 'API key not configured'}
            
        try:
            # URL encoding for VirusTotal
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            
            headers = {
                'x-apikey': API_CONFIG['VIRUSTOTAL_API_KEY']
            }
            
            response = requests.get(vt_url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                return {
                    'available': True,
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'clean': stats.get('undetected', 0),
                    'total_engines': sum(stats.values()),
                    'scan_date': data.get('data', {}).get('attributes', {}).get('last_analysis_date'),
                    'reputation': data.get('data', {}).get('attributes', {}).get('reputation', 0)
                }
            elif response.status_code == 404:
                # URL not found in database, submit for scanning
                self.submit_url_to_virustotal(url)
                return {'available': True, 'status': 'submitted_for_analysis', 'message': 'URL submitted to VirusTotal for analysis'}
            else:
                return {'available': False, 'error': f'API error: {response.status_code}'}
                
        except Exception as e:
            return {'available': False, 'error': str(e)}
    
    def submit_url_to_virustotal(self, url):
        """Submit URL to VirusTotal for analysis"""
        try:
            vt_url = "https://www.virustotal.com/api/v3/urls"
            headers = {
                'x-apikey': API_CONFIG['VIRUSTOTAL_API_KEY']
            }
            data = {'url': url}
            
            response = requests.post(vt_url, headers=headers, data=data, timeout=10)
            return response.status_code == 200
        except:
            return False
    
    def check_google_safe_browsing(self, url):
        """Check URL against Google Safe Browsing API"""
        if not API_CONFIG['GOOGLE_SAFE_BROWSING_API_KEY']:
            return {'available': False, 'reason': 'API key not configured'}
            
        try:
            gsb_url = f"https://safebrowsing.googleapis.com/v4/threats:find?key={API_CONFIG['GOOGLE_SAFE_BROWSING_API_KEY']}"
            
            payload = {
                "client": {
                    "clientId": "cyberguard-platform",
                    "clientVersion": "1.0"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["WINDOWS", "LINUX", "OSX"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            response = requests.post(gsb_url, json=payload, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                matches = data.get('matches', [])
                
                if matches:
                    return {
                        'available': True,
                        'is_threat': True,
                        'threat_types': [match.get('threatType') for match in matches],
                        'platform_types': [match.get('platformType') for match in matches]
                    }
                else:
                    return {'available': True, 'is_threat': False, 'message': 'URL is clean according to Google Safe Browsing'}
            else:
                return {'available': False, 'error': f'API error: {response.status_code}'}
                
        except Exception as e:
            return {'available': False, 'error': str(e)}
    
    def check_urlvoid(self, url):
        """Check URL reputation using URLVoid API"""
        if not API_CONFIG['URLVOID_API_KEY']:
            return {'available': False, 'reason': 'API key not configured'}
            
        try:
            domain = urlparse(url).netloc
            urlvoid_url = f"https://api.urlvoid.com/v1/stats/{API_CONFIG['URLVOID_API_KEY']}/{domain}/"
            
            response = requests.get(urlvoid_url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                detections = data.get('data', {}).get('detections', 0)
                engines_count = data.get('data', {}).get('engines_count', 0)
                
                return {
                    'available': True,
                    'detections': detections,
                    'engines_count': engines_count,
                    'is_malicious': detections > 0,
                    'reputation': 'clean' if detections == 0 else 'suspicious' if detections < 3 else 'malicious'
                }
            else:
                return {'available': False, 'error': f'API error: {response.status_code}'}
                
        except Exception as e:
            return {'available': False, 'error': str(e)}
    
    def check_abuseipdb(self, ip_address):
        """Check IP reputation using AbuseIPDB"""
        if not API_CONFIG['ABUSEIPDB_API_KEY']:
            return {'available': False, 'reason': 'API key not configured'}
            
        try:
            abuseipdb_url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                'Key': API_CONFIG['ABUSEIPDB_API_KEY'],
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            response = requests.get(abuseipdb_url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                abuse_data = data.get('data', {})
                
                return {
                    'available': True,
                    'abuse_confidence': abuse_data.get('abuseConfidencePercentage', 0),
                    'country_code': abuse_data.get('countryCode'),
                    'is_whitelisted': abuse_data.get('isWhitelisted', False),
                    'total_reports': abuse_data.get('totalReports', 0),
                    'last_reported': abuse_data.get('lastReportedAt')
                }
            else:
                return {'available': False, 'error': f'API error: {response.status_code}'}
                
        except Exception as e:
            return {'available': False, 'error': str(e)}
    
    def check_shodan(self, ip_address):
        """Get IP information from Shodan"""
        if not API_CONFIG['SHODAN_API_KEY']:
            return {'available': False, 'reason': 'API key not configured'}
            
        try:
            shodan_url = f"https://api.shodan.io/shodan/host/{ip_address}?key={API_CONFIG['SHODAN_API_KEY']}"
            
            response = requests.get(shodan_url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                return {
                    'available': True,
                    'country': data.get('country_name'),
                    'city': data.get('city'),
                    'org': data.get('org'),
                    'ports': data.get('ports', []),
                    'hostnames': data.get('hostnames', []),
                    'vulns': list(data.get('vulns', {}).keys()),
                    'last_update': data.get('last_update')
                }
            else:
                return {'available': False, 'error': f'API error: {response.status_code}'}
                
        except Exception as e:
            return {'available': False, 'error': str(e)}
    
    def check_ipqualityscore(self, url):
        """Check URL reputation using IPQualityScore"""
        if not API_CONFIG['IPQUALITYSCORE_API_KEY']:
            return {'available': False, 'reason': 'API key not configured'}
            
        try:
            ipqs_url = f"https://www.ipqualityscore.com/api/json/url/{API_CONFIG['IPQUALITYSCORE_API_KEY']}/{urllib.parse.quote(url)}"
            
            response = requests.get(ipqs_url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                return {
                    'available': True,
                    'malware': data.get('malware', False),
                    'phishing': data.get('phishing', False),
                    'suspicious': data.get('suspicious', False),
                    'adult': data.get('adult', False),
                    'risk_score': data.get('risk_score', 0),
                    'country_code': data.get('country_code'),
                    'server': data.get('server'),
                    'category': data.get('category')
                }
            else:
                return {'available': False, 'error': f'API error: {response.status_code}'}
                
        except Exception as e:
            return {'available': False, 'error': str(e)}
    
    def resolve_ip_address(self, domain):
        """Resolve domain to IP address"""
        try:
            result = socket.gethostbyname(domain)
            return result
        except:
            return None

    def analyze_url(self, url, timeout=10):
        """Enhanced URL analysis with multiple API integrations"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Initialize analysis result structure
            analysis_result = {
                'basic_analysis': {},
                'dns_info': {},
                'ssl_info': {},
                'page_content': {},
                'threat_intelligence': {},
                'api_results': {}
            }
            
            # Resolve IP address for IP-based checks
            ip_address = self.resolve_ip_address(domain)
            
            # === API-BASED THREAT INTELLIGENCE ===
            print(f"[INFO] Starting comprehensive analysis for: {url}")
            
            # 1. VirusTotal Analysis
            print("[INFO] Checking VirusTotal...")
            vt_result = self.check_virustotal(url)
            analysis_result['api_results']['virustotal'] = vt_result
            
            if vt_result.get('available') and vt_result.get('malicious', 0) > 0:
                self.risk_score += min(vt_result['malicious'] * 10, 50)
                self.warnings.append(f"VirusTotal detected {vt_result['malicious']} malicious engines")
            
            # 2. Google Safe Browsing
            print("[INFO] Checking Google Safe Browsing...")
            gsb_result = self.check_google_safe_browsing(url)
            analysis_result['api_results']['google_safe_browsing'] = gsb_result
            
            if gsb_result.get('available') and gsb_result.get('is_threat'):
                self.risk_score += 60
                threat_types = ', '.join(gsb_result.get('threat_types', []))
                self.warnings.append(f"Google Safe Browsing flagged as: {threat_types}")
            
            # 3. URLVoid Analysis
            print("[INFO] Checking URLVoid...")
            urlvoid_result = self.check_urlvoid(url)
            analysis_result['api_results']['urlvoid'] = urlvoid_result
            
            if urlvoid_result.get('available') and urlvoid_result.get('detections', 0) > 0:
                self.risk_score += min(urlvoid_result['detections'] * 8, 40)
                self.warnings.append(f"URLVoid detected {urlvoid_result['detections']} security engines flagging this domain")
            
            # 4. IPQualityScore Analysis
            print("[INFO] Checking IPQualityScore...")
            ipqs_result = self.check_ipqualityscore(url)
            analysis_result['api_results']['ipqualityscore'] = ipqs_result
            
            if ipqs_result.get('available'):
                if ipqs_result.get('phishing'):
                    self.risk_score += 70
                    self.warnings.append("IPQualityScore identified this as a phishing site")
                if ipqs_result.get('malware'):
                    self.risk_score += 60
                    self.warnings.append("IPQualityScore detected malware on this site")
                if ipqs_result.get('suspicious'):
                    self.risk_score += 30
                    self.warnings.append("IPQualityScore marked this site as suspicious")
                
                # Add risk score from IPQS
                ipqs_risk = ipqs_result.get('risk_score', 0)
                if ipqs_risk > 75:
                    self.risk_score += 40
                elif ipqs_risk > 50:
                    self.risk_score += 25
                elif ipqs_risk > 25:
                    self.risk_score += 15
            
            # 5. IP-based Analysis (if IP resolved)
            if ip_address:
                print(f"[INFO] Checking IP reputation for: {ip_address}")
                
                # AbuseIPDB
                abuseipdb_result = self.check_abuseipdb(ip_address)
                analysis_result['api_results']['abuseipdb'] = abuseipdb_result
                
                if abuseipdb_result.get('available'):
                    abuse_confidence = abuseipdb_result.get('abuse_confidence', 0)
                    if abuse_confidence > 75:
                        self.risk_score += 50
                        self.warnings.append(f"IP has high abuse confidence: {abuse_confidence}%")
                    elif abuse_confidence > 25:
                        self.risk_score += 20
                        self.warnings.append(f"IP has moderate abuse reports: {abuse_confidence}%")
                
                # Shodan Analysis
                shodan_result = self.check_shodan(ip_address)
                analysis_result['api_results']['shodan'] = shodan_result
                
                if shodan_result.get('available') and shodan_result.get('vulns'):
                    self.risk_score += min(len(shodan_result['vulns']) * 5, 30)
                    self.warnings.append(f"Shodan detected {len(shodan_result['vulns'])} vulnerabilities")
            
            # === BASIC URL PATTERN ANALYSIS ===
            if any(suspicious in domain for suspicious in SUSPICIOUS_DOMAINS):
                self.risk_score += 30
                self.warnings.append(f"URL uses suspicious shortening service: {domain}")
            
            # Check for subdomain spoofing
            if domain.count('.') > 2:
                self.risk_score += 20
                self.warnings.append("Multiple subdomains detected - possible spoofing attempt")
            
            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw', '.cc', '.top', '.click', '.download']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                self.risk_score += 25
                self.warnings.append("Suspicious top-level domain detected")
            
            # Check for URL length
            if len(url) > 100:
                self.risk_score += 15
                self.warnings.append("Unusually long URL detected")
            
            # Check for IP address instead of domain
            if IPADDRESS_AVAILABLE:
                try:
                    ipaddress.ip_address(domain)
                    self.risk_score += 40
                    self.warnings.append("URL uses IP address instead of domain name")
                except ValueError:
                    pass  # Not an IP address, which is good
            
            # Advanced domain analysis
            if WHOIS_AVAILABLE:
                try:
                    domain_info = whois.whois(domain)
                    if domain_info.creation_date:
                        if isinstance(domain_info.creation_date, list):
                            creation_date = domain_info.creation_date[0]
                        else:
                            creation_date = domain_info.creation_date
                        
                        days_old = (datetime.now() - creation_date).days
                        if days_old < 30:
                            self.risk_score += 35
                            self.warnings.append(f"Domain is very new ({days_old} days old)")
                        elif days_old < 90:
                            self.risk_score += 15
                            self.warnings.append(f"Domain is relatively new ({days_old} days old)")
                        
                        analysis_result['basic_analysis']['domain_age'] = days_old
                        analysis_result['basic_analysis']['creation_date'] = str(creation_date)
                    
                    if domain_info.registrar:
                        analysis_result['basic_analysis']['registrar'] = domain_info.registrar
                        
                except Exception as e:
                    self.risk_score += 20
                    self.warnings.append("Unable to retrieve domain registration information")
                    analysis_result['basic_analysis']['whois_error'] = str(e)
            
            # DNS Analysis
            dns_info = get_dns_info(domain)
            analysis_result['dns_info'] = dns_info
            
            if 'error' in dns_info:
                self.risk_score += 15
                self.warnings.append("DNS resolution issues detected")
            
            # SSL Certificate Analysis
            if url.startswith('https://'):
                ssl_info = check_ssl_certificate(domain)
                analysis_result['ssl_info'] = ssl_info
                
                if not ssl_info.get('valid', False):
                    self.risk_score += 30
                    self.warnings.append("Invalid or missing SSL certificate")
                else:
                    self.recommendations.append("SSL certificate is valid")
            else:
                self.risk_score += 25
                self.warnings.append("URL does not use HTTPS encryption")
            
            # Page Content Analysis
            page_data = get_page_content(url, timeout=timeout)
            if page_data.get('content'):
                content_analysis = analyze_page_content(page_data['content'])
                analysis_result['page_content'] = {
                    'status_code': page_data.get('status_code'),
                    'final_url': page_data.get('final_url'),
                    'redirect_count': len(page_data.get('redirect_history', [])),
                    'content_analysis': content_analysis
                }
                
                # Check for redirects
                if len(page_data.get('redirect_history', [])) > 2:
                    self.risk_score += 20
                    self.warnings.append(f"Multiple redirects detected ({len(page_data['redirect_history'])})")
                
                # Check for suspicious content
                if content_analysis.get('suspicious_elements'):
                    self.risk_score += len(content_analysis['suspicious_elements']) * 5
                    self.warnings.extend(content_analysis['suspicious_elements'])
                
            elif page_data.get('error'):
                self.risk_score += 25
                self.warnings.append(f"Unable to access webpage: {page_data['error']}")
                analysis_result['page_content'] = {'error': page_data['error']}
            
            # Homograph attack detection
            if self.detect_homograph_attack(domain):
                self.risk_score += 35
                self.warnings.append("Possible homograph/lookalike domain attack")
            
            # Check for suspicious URL patterns
            suspicious_patterns = [
                r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',  # IP addresses
                r'[a-z]+-[a-z]+-[a-z]+\.(tk|ml|ga|cf)',  # Suspicious domain patterns
                r'(paypal|amazon|google|microsoft|apple)-.*\.',  # Brand impersonation
                r'secure.*login',  # Fake security pages
                r'verify.*account',  # Account verification scams
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, url.lower()):
                    self.risk_score += 20
                    self.warnings.append(f"Suspicious URL pattern detected")
                    break
            
            result = self.get_analysis_result()
            result['detailed_analysis'] = analysis_result
            return result
            
        except Exception as e:
            return {
                'risk_level': 'Error',
                'risk_score': 0,
                'warnings': [f"Error analyzing URL: {str(e)}"],
                'recommendations': ['Please check the URL format and try again']
            }
    
    def detect_homograph_attack(self, domain):
        """Detect potential homograph attacks"""
        # Common homograph characters
        homographs = {
            'a': ['а', 'α', 'ɑ'],  # Cyrillic a, Greek alpha
            'e': ['е', 'ε'],       # Cyrillic e, Greek epsilon
            'o': ['о', 'ο', '0'],  # Cyrillic o, Greek omicron, zero
            'p': ['р', 'ρ'],       # Cyrillic p, Greek rho
            'c': ['с', 'ϲ'],       # Cyrillic c, Greek c
            'x': ['х', 'χ'],       # Cyrillic x, Greek chi
            'y': ['у', 'γ'],       # Cyrillic y, Greek gamma
        }
        
        for char in domain:
            for latin_char, lookalikes in homographs.items():
                if char in lookalikes:
                    return True
        return False

    def analyze_email(self, email_content, sender_email=""):
        """Analyze email content for phishing indicators"""
        content_lower = email_content.lower()
        
        # Check for phishing keywords
        found_keywords = [kw for kw in PHISHING_KEYWORDS if kw in content_lower]
        if found_keywords:
            self.risk_score += len(found_keywords) * 10
            self.warnings.append(f"Suspicious keywords found: {', '.join(found_keywords)}")
        
        # Check for urgent language
        urgent_phrases = ['urgent', 'immediate', 'expires today', 'act now', 'limited time']
        urgent_found = [phrase for phrase in urgent_phrases if phrase in content_lower]
        if urgent_found:
            self.risk_score += 25
            self.warnings.append("Email contains urgent/pressure language")
        
        # Check for suspicious links
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, email_content)
        
        if urls:
            for url in urls:
                if any(suspicious in url.lower() for suspicious in SUSPICIOUS_DOMAINS):
                    self.risk_score += 20
                    self.warnings.append(f"Email contains suspicious shortened URL: {url}")
        
        # Check sender email
        if sender_email:
            if '@' not in sender_email or sender_email.count('@') != 1:
                self.risk_score += 30
                self.warnings.append("Invalid sender email format")
            else:
                domain = sender_email.split('@')[1].lower()
                # Check for domain spoofing
                legitimate_domains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com']
                similar_domains = ['gmai1.com', 'yah00.com', 'outlook.co', 'hotmai1.com']
                
                if any(similar in domain for similar in similar_domains):
                    self.risk_score += 40
                    self.warnings.append("Sender domain appears to be spoofing a legitimate service")
        
        return self.get_analysis_result()

    def analyze_media_file(self, file_path, filename):
        """Analyze uploaded media file for potential threats"""
        try:
            # Check file extension vs actual file type
            file_extension = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
            
            # Get actual file type using python-magic
            try:
                if MAGIC_AVAILABLE:
                    file_type = magic.from_file(file_path, mime=True)
                else:
                    file_type = "unknown"
            except:
                file_type = "unknown"
            
            # Check for extension spoofing
            extension_mime_map = {
                'jpg': 'image/jpeg',
                'jpeg': 'image/jpeg',
                'png': 'image/png',
                'gif': 'image/gif',
                'pdf': 'application/pdf',
                'txt': 'text/plain',
                'mp4': 'video/mp4',
                'avi': 'video/x-msvideo',
                'mov': 'video/quicktime'
            }
            
            expected_mime = extension_mime_map.get(file_extension, 'unknown')
            if expected_mime != 'unknown' and expected_mime not in file_type:
                self.risk_score += 50
                self.warnings.append(f"File extension mismatch: {file_extension} file claims to be {file_type}")
            
            # Check file size
            file_size = os.path.getsize(file_path)
            if file_size > 10 * 1024 * 1024:  # 10MB
                self.risk_score += 20
                self.warnings.append("Large file size detected - exercise caution")
            
            # Check if executable disguised as media
            executable_types = ['application/x-executable', 'application/x-dosexec', 'application/x-msdownload']
            if any(exe_type in file_type for exe_type in executable_types):
                self.risk_score += 80
                self.warnings.append("File appears to be executable disguised as media")
            
            # Calculate file hash for reputation checking
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            
            file_hash = sha256_hash.hexdigest()
            
            # Add file info to analysis
            analysis = self.get_analysis_result()
            analysis['file_info'] = {
                'filename': filename,
                'size': f"{file_size / 1024:.2f} KB",
                'type': file_type,
                'hash': file_hash[:16] + "..."  # Show partial hash
            }
            
            return analysis
            
        except Exception as e:
            return {
                'risk_level': 'Error',
                'risk_score': 0,
                'warnings': [f"Error analyzing file: {str(e)}"],
                'recommendations': ['Please check the file and try again']
            }

    def get_analysis_result(self):
        """Return analysis result with risk level"""
        if self.risk_score >= 70:
            risk_level = "High Risk"
            self.recommendations.extend([
                "DO NOT interact with this content",
                "Report as suspicious",
                "Delete immediately"
            ])
        elif self.risk_score >= 40:
            risk_level = "Medium Risk"
            self.recommendations.extend([
                "Exercise extreme caution",
                "Verify through official channels",
                "Do not provide personal information"
            ])
        elif self.risk_score >= 20:
            risk_level = "Low Risk"
            self.recommendations.extend([
                "Be cautious and verify authenticity",
                "Look for additional warning signs"
            ])
        else:
            risk_level = "Low Risk"
            self.recommendations.append("Content appears relatively safe, but always stay vigilant")
        
        return {
            'risk_level': risk_level,
            'risk_score': min(self.risk_score, 100),
            'warnings': self.warnings,
            'recommendations': self.recommendations
        }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scanner')
def scanner():
    return render_template('scanner.html')

@app.route('/education')
def education():
    return render_template('education.html')

@app.route('/advanced')
def advanced():
    return render_template('advanced.html')

@app.route('/api/scan-url', methods=['POST'])
def scan_url():
    data = request.get_json()
    url = data.get('url', '')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    analyzer = SecurityAnalyzer()
    result = analyzer.analyze_url(url)
    
    return jsonify(result)

@app.route('/api/scan-email', methods=['POST'])
def scan_email():
    data = request.get_json()
    email_content = data.get('email_content', '')
    sender_email = data.get('sender_email', '')
    
    if not email_content:
        return jsonify({'error': 'Email content is required'}), 400
    
    analyzer = SecurityAnalyzer()
    result = analyzer.analyze_email(email_content, sender_email)
    
    return jsonify(result)

@app.route('/api/scan-file', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400
    
    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)
    
    try:
        analyzer = SecurityAnalyzer()
        result = analyzer.analyze_media_file(file_path, filename)
        
        # Clean up uploaded file
        os.remove(file_path)
        
        return jsonify(result)
    except Exception as e:
        # Clean up uploaded file even if analysis fails
        if os.path.exists(file_path):
            os.remove(file_path)
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

@app.route('/api/preview-page', methods=['POST'])
def preview_page():
    """Get safe preview of a webpage"""
    client_ip = request.remote_addr
    print(f"[DEBUG] Preview request from {client_ip}")
    
    # Rate limiting
    if not rate_limit_check(client_ip):
        print(f"[DEBUG] Rate limit exceeded for {client_ip}")
        return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429
    
    data = request.get_json()
    url = data.get('url', '')
    print(f"[DEBUG] Received URL: {url}")
    
    if not url:
        print("[DEBUG] No URL provided")
        return jsonify({'error': 'URL is required'}), 400
    
    try:
        # Get page content
        page_data = get_page_content(url, timeout=15)
        
        if page_data.get('error'):
            return jsonify({
                'error': page_data['error'],
                'accessible': False
            })
        
        # Extract basic page information
        content = page_data.get('content', '')
        
        # Extract title
        title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
        title = title_match.group(1).strip() if title_match else 'No title found'
        
        # Extract meta description
        desc_match = re.search(r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']*)["\']', content, re.IGNORECASE)
        description = desc_match.group(1) if desc_match else 'No description available'
        
        # Basic content analysis
        content_analysis = analyze_page_content(content)
        
        # Extract favicon
        favicon_match = re.search(r'<link[^>]*rel=["\'](?:shortcut )?icon["\'][^>]*href=["\']([^"\']*)["\']', content, re.IGNORECASE)
        favicon = favicon_match.group(1) if favicon_match else None
        if favicon and not favicon.startswith('http'):
            favicon = urljoin(url, favicon)
        
        # Capture webpage screenshot (only if selenium is available)
        screenshot_data = {'success': False, 'error': 'Screenshot functionality disabled - selenium not available'}
        if SELENIUM_AVAILABLE:
            print("Capturing webpage screenshot...")
            screenshot_data = capture_webpage_screenshot(url, timeout=12)
        else:
            print("Screenshot functionality disabled - selenium not available")
        
        preview_data = {
            'accessible': True,
            'title': title[:200],  # Limit title length
            'description': description[:500],  # Limit description length
            'favicon': favicon,
            'final_url': page_data.get('final_url', url),
            'status_code': page_data.get('status_code'),
            'redirect_count': len(page_data.get('redirect_history', [])),
            'content_analysis': content_analysis,
            'screenshot_available': screenshot_data.get('success', False),
            'screenshot_data': screenshot_data.get('screenshot_data') if screenshot_data.get('success') else None,
            'screenshot_error': screenshot_data.get('error') if not screenshot_data.get('success') else None,
            'screenshot_dimensions': screenshot_data.get('dimensions') if screenshot_data.get('success') else None,
            'page_size': len(content),
            'load_time': page_data.get('load_time', 'N/A')
        }
        
        return jsonify(preview_data)
        
    except Exception as e:
        return jsonify({
            'error': f'Failed to preview page: {str(e)}',
            'accessible': False
        }), 500

@app.route('/api/bulk-scan', methods=['POST'])
def bulk_scan():
    """Scan multiple URLs at once with improved error handling"""
    client_ip = request.remote_addr
    
    if not rate_limit_check(client_ip):
        return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429
    
    data = request.get_json()
    urls = data.get('urls', [])
    
    if not urls or len(urls) > 10:  # Limit to 10 URLs
        return jsonify({'error': 'Please provide 1-10 URLs for bulk scanning'}), 400
    
    results = []
    scan_stats = {
        'successful': 0,
        'failed': 0,
        'timeouts': 0,
        'connection_errors': 0
    }
    
    for i, url in enumerate(urls):
        url = url.strip()
        if not url:
            continue
            
        try:
            print(f"Scanning URL {i+1}/{len(urls)}: {url}")
            analyzer = SecurityAnalyzer()
            
            # Use shorter timeout for bulk scanning
            result = analyzer.analyze_url(url, timeout=8)
            
            results.append({
                'url': url,
                'analysis': result,
                'status': 'success'
            })
            scan_stats['successful'] += 1
            
        except Exception as e:
            error_msg = str(e)
            error_type = 'error'
            
            # Categorize error types
            if 'timeout' in error_msg.lower() or 'timed out' in error_msg.lower():
                error_type = 'timeout'
                scan_stats['timeouts'] += 1
                error_msg = 'Connection timeout - Website took too long to respond'
            elif 'connection' in error_msg.lower():
                error_type = 'connection_error'
                scan_stats['connection_errors'] += 1
                error_msg = 'Connection failed - Unable to reach website'
            else:
                scan_stats['failed'] += 1
            
            results.append({
                'url': url,
                'error': error_msg,
                'error_type': error_type,
                'status': 'failed'
            })
            
            print(f"Error scanning {url}: {error_msg}")
    
    return jsonify({
        'results': results,
        'total_scanned': len(results),
        'statistics': scan_stats,
        'scan_time': datetime.now().isoformat()
    })

@app.route('/api/threat-report', methods=['GET'])
def threat_report():
    """Get daily threat statistics with API status"""
    
    # Check API availability
    api_status = {}
    for api_name, api_key in API_CONFIG.items():
        api_status[api_name.lower().replace('_api_key', '')] = {
            'configured': bool(api_key),
            'status': 'active' if api_key else 'not_configured'
        }
    
    report = {
        'date': datetime.now().isoformat(),
        'total_threats_blocked': 1547,
        'phishing_attempts': 892,
        'malware_detected': 334,
        'suspicious_domains': 321,
        'api_status': api_status,
        'enhanced_detection': any(api_key for api_key in API_CONFIG.values()),
        'top_threats': [
            {'type': 'Phishing Email', 'count': 456, 'trend': '+12%'},
            {'type': 'Fake Banking Site', 'count': 234, 'trend': '+8%'},
            {'type': 'Malicious Download', 'count': 189, 'trend': '-5%'},
            {'type': 'Social Engineering', 'count': 167, 'trend': '+15%'},
            {'type': 'Credential Theft', 'count': 123, 'trend': '+3%'}
        ],
        'security_tips': [
            'Always verify sender identity before clicking email links',
            'Check for HTTPS encryption on sensitive websites',
            'Keep your antivirus software updated',
            'Be cautious of urgent or threatening messages',
            'Use strong, unique passwords for each account'
        ]
    }
    
    return jsonify(report)

def generate_pdf_report(data):
    """Generate a PDF report from analysis data"""
    if not REPORTLAB_AVAILABLE:
        return None
    
    try:
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        
        # Get styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#2c3e50')
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.HexColor('#34495e')
        )
        
        normal_style = styles['Normal']
        
        # Build content
        content = []
        
        # Title
        content.append(Paragraph("CyberGuard Security Analysis Report", title_style))
        content.append(Spacer(1, 20))
        
        # Report metadata
        timestamp = data.get('timestamp', datetime.now().isoformat())
        content.append(Paragraph(f"<b>Generated:</b> {timestamp}", normal_style))
        content.append(Paragraph(f"<b>Analysis Type:</b> {data.get('type', 'Unknown')}", normal_style))
        content.append(Spacer(1, 20))
        
        # Analysis results
        analysis = data.get('analysis', {})
        
        if 'url' in analysis:
            content.append(Paragraph("URL Analysis", heading_style))
            content.append(Paragraph(f"<b>URL:</b> {analysis['url']}", normal_style))
            content.append(Paragraph(f"<b>Status:</b> {analysis.get('status', 'Unknown')}", normal_style))
            
            if 'risk_score' in analysis:
                risk_color = colors.red if analysis['risk_score'] > 70 else colors.orange if analysis['risk_score'] > 40 else colors.green
                content.append(Paragraph(f"<b>Risk Score:</b> <font color='{risk_color}'>{analysis['risk_score']}/100</font>", normal_style))
            
            content.append(Spacer(1, 15))
        
        # Security warnings
        if 'warnings' in analysis and analysis['warnings']:
            content.append(Paragraph("Security Warnings", heading_style))
            for warning in analysis['warnings']:
                content.append(Paragraph(f"• {warning}", normal_style))
            content.append(Spacer(1, 15))
        
        # Threats detected
        if 'threats' in analysis and analysis['threats']:
            content.append(Paragraph("Threats Detected", heading_style))
            threat_data = []
            threat_data.append(['Threat Type', 'Severity', 'Description'])
            
            for threat in analysis['threats']:
                threat_data.append([
                    threat.get('type', 'Unknown'),
                    threat.get('severity', 'Medium'),
                    threat.get('description', 'No description available')
                ])
            
            threat_table = Table(threat_data)
            threat_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            content.append(threat_table)
            content.append(Spacer(1, 15))
        
        # Technical details
        if 'technical_details' in analysis:
            content.append(Paragraph("Technical Details", heading_style))
            tech_details = analysis['technical_details']
            
            if isinstance(tech_details, dict):
                for key, value in tech_details.items():
                    content.append(Paragraph(f"<b>{key.replace('_', ' ').title()}:</b> {value}", normal_style))
            else:
                content.append(Paragraph(str(tech_details), normal_style))
            
            content.append(Spacer(1, 15))
        
        # Recommendations
        content.append(Paragraph("Security Recommendations", heading_style))
        recommendations = [
            "Always verify the legitimacy of websites before entering sensitive information",
            "Keep your browser and security software up to date",
            "Be cautious of shortened URLs and suspicious links",
            "Use strong, unique passwords for each account",
            "Enable two-factor authentication where possible"
        ]
        
        for rec in recommendations:
            content.append(Paragraph(f"• {rec}", normal_style))
        
        content.append(Spacer(1, 20))
        
        # Footer
        footer_style = ParagraphStyle(
            'Footer',
            parent=styles['Normal'],
            fontSize=10,
            alignment=TA_CENTER,
            textColor=colors.grey
        )
        content.append(Paragraph("Generated by CyberGuard Security Platform v1.0", footer_style))
        
        # Build PDF
        doc.build(content)
        buffer.seek(0)
        return buffer
        
    except Exception as e:
        print(f"PDF generation error: {e}")
        return None

@app.route('/api/export-report', methods=['POST'])
def export_report():
    """Export analysis report as PDF"""
    if not REPORTLAB_AVAILABLE:
        return jsonify({
            'success': False,
            'error': 'PDF generation not available. ReportLab library not installed.'
        }), 500
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided for export'
            }), 400
        
        # Generate PDF
        pdf_buffer = generate_pdf_report(data)
        if not pdf_buffer:
            return jsonify({
                'success': False,
                'error': 'Failed to generate PDF report'
            }), 500
        
        # Return PDF as base64 for download
        pdf_data = pdf_buffer.getvalue()
        pdf_base64 = base64.b64encode(pdf_data).decode('utf-8')
        
        return jsonify({
            'success': True,
            'pdf_data': pdf_base64,
            'filename': f"cyberguard-report-{datetime.now().strftime('%Y-%m-%d-%H%M%S')}.pdf",
            'size': len(pdf_data)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Export failed: {str(e)}'
        }), 500

@app.route('/api/api-status', methods=['GET'])
def api_status():
    """Get API configuration status"""
    status = {}
    
    for api_name, api_key in API_CONFIG.items():
        clean_name = api_name.lower().replace('_api_key', '')
        status[clean_name] = {
            'configured': bool(api_key),
            'status': 'active' if api_key else 'not_configured',
            'description': get_api_description(clean_name)
        }
    
    return jsonify({
        'api_status': status,
        'total_configured': sum(1 for key in API_CONFIG.values() if key),
        'total_available': len(API_CONFIG),
        'enhancement_active': any(api_key for api_key in API_CONFIG.values())
    })

def get_api_description(api_name):
    """Get description for each API"""
    descriptions = {
        'virustotal': 'Multi-engine malware detection',
        'google_safe_browsing': 'Google threat database',
        'urlvoid': 'Domain reputation analysis',
        'ipqualityscore': 'Advanced phishing detection',
        'abuseipdb': 'IP reputation and abuse reports',
        'shodan': 'Internet device vulnerability data',
        'phishtank': 'Community phishing database',
        'hibp': 'Data breach monitoring'
    }
    return descriptions.get(api_name, 'Security intelligence API')

@app.route('/api/domain-info', methods=['POST'])
def domain_info():
    """Get comprehensive domain information"""
    data = request.get_json()
    domain = data.get('domain', '').lower().strip()
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    # Remove protocol if present
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.split('/')[0]  # Remove path
    
    try:
        info = {
            'domain': domain,
            'whois': {},
            'dns': {},
            'ssl': {},
            'reputation': {},
            'analysis_timestamp': datetime.now().isoformat()
        }
        
        # WHOIS information
        if WHOIS_AVAILABLE:
            try:
                whois_info = whois.whois(domain)
                info['whois'] = {
                    'registrar': whois_info.registrar,
                    'creation_date': str(whois_info.creation_date) if whois_info.creation_date else None,
                    'expiration_date': str(whois_info.expiration_date) if whois_info.expiration_date else None,
                    'name_servers': whois_info.name_servers if whois_info.name_servers else [],
                    'status': whois_info.status if whois_info.status else [],
                }
            except Exception as e:
                info['whois'] = {'error': str(e)}
        else:
            info['whois'] = {'error': 'WHOIS analysis not available - python-whois not installed'}
        
        # DNS information
        info['dns'] = get_dns_info(domain)
        
        # SSL information
        info['ssl'] = check_ssl_certificate(domain)
        
        # Basic reputation check (placeholder)
        info['reputation'] = {
            'risk_score': 'Low',
            'categories': [],
            'last_seen': None,
            'threat_types': []
        }
        
        return jsonify(info)
        
    except Exception as e:
        return jsonify({'error': f'Failed to analyze domain: {str(e)}'}), 500

@app.route('/test_preview.html')
def test_preview():
    """Serve test page for debugging"""
    with open('test_preview.html', 'r') as f:
        return f.read(), 200, {'Content-Type': 'text/html'}

if __name__ == '__main__':
    # Get port from environment variable for deployment platforms
    port = int(os.environ.get('PORT', 5000))
    # Set debug based on environment
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    app.run(debug=debug_mode, host='0.0.0.0', port=port)