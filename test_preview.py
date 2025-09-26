import requests
import json

def test_preview_api():
    """Test the Safe Page Preview API"""
    url = "http://127.0.0.1:5000/api/preview-page"
    test_data = {
        "url": "https://example.com"
    }
    
    try:
        print("Testing Safe Page Preview API...")
        response = requests.post(url, json=test_data)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        if response.status_code == 200:
            print("✅ API is working!")
            data = response.json()
            if data.get('accessible'):
                print(f"✅ Page is accessible: {data.get('title')}")
                if data.get('screenshot_available'):
                    print("✅ Screenshot captured")
                else:
                    print("⚠️ Screenshot not available:", data.get('screenshot_error', 'Unknown reason'))
            else:
                print("❌ Page not accessible:", data.get('error'))
        else:
            print("❌ API error:", response.json())
            
    except Exception as e:
        print(f"❌ Test failed: {e}")

if __name__ == "__main__":
    test_preview_api()