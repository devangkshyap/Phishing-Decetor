from PIL import Image, ImageDraw, ImageFont
import io
import base64

def create_placeholder_screenshot(url, width=800, height=600):
    """Create a placeholder screenshot when browser automation fails"""
    try:
        # Create a new image with white background
        image = Image.new('RGB', (width, height), color='white')
        draw = ImageDraw.Draw(image)
        
        # Try to use a default font, fall back to basic if not available
        try:
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

# Test the function
if __name__ == "__main__":
    result = create_placeholder_screenshot("https://example.com")
    print(f"Placeholder screenshot created: {result['success']}")
    if result['success']:
        print(f"Size: {result['screenshot_size']} bytes")
        print(f"Dimensions: {result['dimensions']}")