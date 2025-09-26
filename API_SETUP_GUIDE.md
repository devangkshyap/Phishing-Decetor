# CyberGuard Platform - API Configuration Guide

## 🔌 API Integrations Available

Your cybersecurity platform can now integrate with multiple threat intelligence APIs for highly accurate results:

### 1. **VirusTotal API** (Highly Recommended)
- **What it does**: Scans URLs against 70+ antivirus engines
- **Free Tier**: 4 requests per minute, 500 requests per day
- **Signup**: https://www.virustotal.com/gui/join-us
- **API Key**: Get from https://www.virustotal.com/gui/my-apikey
- **Environment Variable**: `VIRUSTOTAL_API_KEY`

### 2. **Google Safe Browsing API** (Recommended)
- **What it does**: Checks against Google's massive threat database
- **Free Tier**: 10,000 requests per day
- **Signup**: https://console.developers.google.com/
- **Setup**: Enable Safe Browsing API and create credentials
- **Environment Variable**: `GOOGLE_SAFE_BROWSING_API_KEY`

### 3. **URLVoid API**
- **What it does**: Domain reputation from multiple security engines
- **Free Tier**: 1,000 requests per month
- **Signup**: https://www.urlvoid.com/api/
- **Environment Variable**: `URLVOID_API_KEY`

### 4. **IPQualityScore API**
- **What it does**: Advanced phishing and malware detection
- **Free Tier**: 5,000 lookups per month
- **Signup**: https://www.ipqualityscore.com/create-account
- **Environment Variable**: `IPQUALITYSCORE_API_KEY`

### 5. **AbuseIPDB API**
- **What it does**: IP reputation and abuse reports
- **Free Tier**: 1,000 checks per day
- **Signup**: https://www.abuseipdb.com/register
- **Environment Variable**: `ABUSEIPDB_API_KEY`

### 6. **Shodan API**
- **What it does**: Internet-connected device information and vulnerabilities
- **Free Tier**: 100 queries per month
- **Signup**: https://account.shodan.io/register
- **Environment Variable**: `SHODAN_API_KEY`

## 🚀 Setup Instructions

### Method 1: Environment Variables (Recommended)
```bash
# Windows (PowerShell)
$env:VIRUSTOTAL_API_KEY="your_virustotal_api_key_here"
$env:GOOGLE_SAFE_BROWSING_API_KEY="your_google_api_key_here"
$env:IPQUALITYSCORE_API_KEY="your_ipqs_api_key_here"

# Linux/Mac
export VIRUSTOTAL_API_KEY="your_virustotal_api_key_here"
export GOOGLE_SAFE_BROWSING_API_KEY="your_google_api_key_here"
export IPQUALITYSCORE_API_KEY="your_ipqs_api_key_here"
```

### Method 2: Create .env file
Create a `.env` file in your project root:
```
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
GOOGLE_SAFE_BROWSING_API_KEY=your_google_api_key_here
URLVOID_API_KEY=your_urlvoid_api_key_here
IPQUALITYSCORE_API_KEY=your_ipqs_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
SHODAN_API_KEY=your_shodan_api_key_here
```

## 📊 What You Get With API Integration

### Enhanced Accuracy
- **Multi-engine validation**: Cross-reference threats across multiple sources
- **Real-time data**: Get the latest threat intelligence
- **Reduced false positives**: Multiple sources confirm threats
- **Comprehensive coverage**: Different APIs catch different types of threats

### Detailed Analysis Reports
- **Threat classification**: Malware, phishing, suspicious, etc.
- **Confidence scores**: Know how certain the detection is
- **Historical data**: See when threats were first detected
- **Geographic information**: Country and organization data
- **Vulnerability information**: Known security issues

### Example Enhanced Results
```json
{
  "risk_score": 85,
  "risk_level": "High Risk",
  "api_results": {
    "virustotal": {
      "malicious": 15,
      "suspicious": 3,
      "total_engines": 70
    },
    "google_safe_browsing": {
      "is_threat": true,
      "threat_types": ["SOCIAL_ENGINEERING"]
    },
    "ipqualityscore": {
      "phishing": true,
      "risk_score": 90
    }
  }
}
```

## 🔒 Privacy & Security

- **No sensitive data logged**: Only URLs are sent to APIs
- **Rate limiting**: Built-in protection against API abuse
- **Timeout handling**: Prevents hanging requests
- **Error handling**: Graceful fallbacks when APIs are unavailable

## 🆓 Cost-Effective Usage

All listed APIs have generous free tiers perfect for:
- **Educational projects**
- **Small business security**
- **Personal cybersecurity research**
- **Proof of concept implementations**

## 🚨 Quick Start (Free APIs)

For immediate enhanced results, start with these free APIs:
1. **VirusTotal** (most important) - Sign up and get API key
2. **Google Safe Browsing** - Enable in Google Cloud Console
3. **IPQualityScore** - Quick signup with generous free tier

Even with just these 3 APIs, you'll get enterprise-level threat detection!

## 📞 Support

If you need help setting up any APIs:
1. Check the API documentation links above
2. Each API has detailed setup guides
3. Most APIs have community forums
4. Free tier support is usually available

**Note**: The platform works perfectly without API keys using built-in heuristics, but API integration provides professional-grade accuracy.