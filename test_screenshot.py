#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_screenshot_functionality():
    """Test the screenshot functionality step by step"""
    print("🔍 Testing screenshot functionality...")
    
    # Test 1: Import check
    print("\n1. Testing imports...")
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from webdriver_manager.chrome import ChromeDriverManager
        from selenium.webdriver.chrome.service import Service
        from PIL import Image
        import io
        import base64
        print("✅ All imports successful")
    except Exception as e:
        print(f"❌ Import failed: {e}")
        return False
    
    # Test 2: Chrome driver setup
    print("\n2. Testing Chrome driver setup...")
    try:
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--window-size=1920,1080')
        
        print("   Setting up ChromeDriverManager...")
        service = Service(ChromeDriverManager().install())
        print("   ChromeDriverManager setup successful")
        
        print("   Creating Chrome driver...")
        driver = webdriver.Chrome(service=service, options=chrome_options)
        print("✅ Chrome driver created successfully")
        
        # Test 3: Simple screenshot
        print("\n3. Testing screenshot capture...")
        driver.get("https://example.com")
        screenshot = driver.get_screenshot_as_png()
        print(f"✅ Screenshot captured: {len(screenshot)} bytes")
        
        # Test 4: PIL processing
        print("\n4. Testing PIL processing...")
        image = Image.open(io.BytesIO(screenshot))
        print(f"✅ PIL image created: {image.size}")
        
        driver.quit()
        print("\n🎉 All tests passed! Screenshot functionality is working.")
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        if 'driver' in locals():
            try:
                driver.quit()
            except:
                pass
        return False

if __name__ == "__main__":
    test_screenshot_functionality()