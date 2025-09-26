#!/usr/bin/env python3

import requests
import json

def test_screenshot_api():
    """Test the screenshot API endpoint"""
    print("🔍 Testing screenshot API...")
    
    try:
        # Test URL analysis endpoint which includes screenshot
        test_url = "https://example.com"
        
        response = requests.post(
            'http://127.0.0.1:5000/analyze',
            json={'url': test_url, 'analysis_type': 'full'},
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            
            print(f"✅ API response received")
            print(f"Status: {data.get('status', 'unknown')}")
            
            if 'screenshot' in data:
                screenshot_info = data['screenshot']
                print(f"Screenshot success: {screenshot_info.get('success', False)}")
                if screenshot_info.get('success'):
                    print(f"Screenshot size: {screenshot_info.get('screenshot_size', 0)} bytes")
                    print(f"Dimensions: {screenshot_info.get('dimensions', 'unknown')}")
                    print(f"Is placeholder: {screenshot_info.get('is_placeholder', False)}")
                else:
                    print(f"Screenshot error: {screenshot_info.get('error', 'unknown error')}")
            else:
                print("❌ No screenshot data in response")
        else:
            print(f"❌ API request failed with status: {response.status_code}")
            print(f"Response: {response.text[:200]}...")
            
    except Exception as e:
        print(f"❌ Test failed: {e}")

if __name__ == "__main__":
    test_screenshot_api()