#!/usr/bin/env python3

import requests
import json
import base64

def test_pdf_export():
    """Test the PDF export functionality"""
    print("🔍 Testing PDF export functionality...")
    
    # Sample analysis data
    test_data = {
        "type": "URL",
        "timestamp": "2025-09-26T09:30:00Z",
        "analysis": {
            "url": "https://example.com",
            "status": "Safe",
            "risk_score": 25,
            "warnings": [
                "Domain is very new (less than 30 days old)",
                "Limited SSL certificate information"
            ],
            "threats": [
                {
                    "type": "Suspicious Domain",
                    "severity": "Low",
                    "description": "Domain has limited reputation data"
                }
            ],
            "technical_details": {
                "ip_address": "93.184.216.34",
                "server": "ECS (dcb/7F83)",
                "ssl_grade": "A+",
                "response_time": "245ms"
            }
        },
        "platform": "CyberGuard Security Platform",
        "version": "1.0"
    }
    
    try:
        response = requests.post(
            'http://127.0.0.1:5000/api/export-report',
            json=test_data,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            
            if result.get('success'):
                print("✅ PDF export successful!")
                print(f"Filename: {result.get('filename')}")
                print(f"PDF size: {result.get('size')} bytes")
                
                # Save the PDF file for testing
                pdf_data = base64.b64decode(result['pdf_data'])
                with open('test_report.pdf', 'wb') as f:
                    f.write(pdf_data)
                print("✅ Test PDF saved as 'test_report.pdf'")
                
                return True
            else:
                print(f"❌ PDF export failed: {result.get('error')}")
                return False
        else:
            print(f"❌ HTTP error: {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False

if __name__ == "__main__":
    test_pdf_export()