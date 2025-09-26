# CyberGuard - Cybersecurity Education Platform

A comprehensive cybersecurity education and awareness platform designed for students and professionals. This platform provides advanced threat analysis capabilities with educational content to help users identify and protect themselves from cyber threats.

## 🚀 Features

### Security Scanner
- **URL Analysis**: Detect phishing URLs, suspicious domains, and malicious links
- **Email Analysis**: Identify phishing emails, social engineering attempts, and suspicious content
- **Media File Scanner**: Analyze uploaded files for malware, extension spoofing, and security threats

### Educational Content
- **Phishing Awareness**: Learn to identify phishing attempts and social engineering tactics
- **URL Security**: Understand URL structure and identify suspicious patterns
- **File Security**: Best practices for handling and analyzing media files
- **Interactive Quiz**: Test your knowledge with real-world scenarios

### Advanced Features
- Real-time threat assessment with risk scoring
- Domain reputation checking and WHOIS analysis
- File integrity verification and hash analysis
- Comprehensive security recommendations
- Progress tracking and learning analytics

## 🛠️ Technology Stack

### Frontend
- **HTML5/CSS3**: Modern, responsive design with unique styling
- **JavaScript (ES6+)**: Interactive features and dynamic content
- **Font Awesome**: Professional icons and visual elements

### Backend
- **Flask**: Python web framework for API endpoints
- **Python Libraries**:
  - `requests`: HTTP requests for external API calls
  - `python-whois`: Domain registration information
  - `dnspython`: DNS resolution and analysis
  - `python-magic`: File type detection and analysis

## 📋 Installation & Setup

### Prerequisites
- Python 3.8 or higher
- pip (Python package installer)

### Step 1: Clone/Download the Project
```bash
# If using git
git clone <repository-url>
cd cybersecurity-platform

# Or download and extract the project files
```

### Step 2: Create Virtual Environment (Recommended)
```bash
python -m venv venv

# On Windows
venv\Scripts\activate

# On macOS/Linux
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Run the Application
```bash
python app.py
```

The application will be available at: `http://localhost:5000`

## 🎯 Usage Guide

### 1. Home Page
- Overview of platform features
- Navigation to different sections
- Statistics and key information

### 2. Security Scanner
- **URL Scanner**: Enter suspicious URLs for analysis
- **Email Analyzer**: Paste email content and sender information
- **File Scanner**: Upload media files for security analysis

### 3. Education Center
- Learn about different types of cyber threats
- Interactive examples and case studies
- Take the knowledge quiz to test understanding

## 🔍 How It Works

### URL Analysis
The platform analyzes URLs for:
- Domain age and reputation
- Suspicious patterns and typosquatting
- URL shorteners and redirects
- SSL certificate status
- Subdomain analysis

### Email Analysis
Email content is examined for:
- Phishing keywords and phrases
- Urgent language patterns
- Suspicious links and attachments
- Sender authenticity verification
- Social engineering indicators

### File Analysis
Uploaded files are checked for:
- File type verification vs extension
- Malware signature detection
- Extension spoofing attempts
- File size and integrity analysis
- Hash-based reputation checking

## 🎓 Educational Value

This platform is designed for:
- **Students**: Learn cybersecurity fundamentals
- **Professionals**: Enhance security awareness
- **Educators**: Teaching tool for cybersecurity concepts
- **Organizations**: Employee security training

## 🔒 Security & Privacy

- No sensitive data is permanently stored
- Files are automatically deleted after analysis
- All analysis is performed locally
- Educational examples use safe, simulated threats
- No actual malicious content is distributed

## 🚧 Development

### Project Structure
```
cybersecurity-platform/
├── app.py                 # Flask application
├── requirements.txt       # Python dependencies
├── static/
│   ├── css/
│   │   └── style.css     # Main stylesheet
│   └── js/
│       ├── main.js       # Core JavaScript
│       ├── scanner.js    # Scanner functionality
│       └── education.js  # Education features
├── templates/
│   ├── index.html        # Home page
│   ├── scanner.html      # Security scanner
│   └── education.html    # Education center
└── uploads/              # Temporary file storage
```

### Adding New Features
1. **New Scanner Type**: Add endpoint in `app.py` and update scanner.js
2. **Educational Content**: Modify `education.html` and add interactive elements
3. **UI Improvements**: Update `style.css` with new components

### API Endpoints
- `POST /api/scan-url`: Analyze URL security
- `POST /api/scan-email`: Analyze email content
- `POST /api/scan-file`: Analyze uploaded files

## 🤝 Contributing

This is an educational project. Suggestions for improvements:
- Additional threat detection algorithms
- More educational content and examples
- Enhanced user interface features
- Integration with threat intelligence feeds

## ⚠️ Disclaimer

This platform is designed for **educational purposes only**. It should not be used as the sole security solution for production environments. Always use comprehensive security tools and follow industry best practices for cybersecurity.

## 📄 License

This project is created for educational purposes. Please ensure compliance with your institution's academic integrity policies.

## 🎉 Final Year Project

This cybersecurity education platform demonstrates:
- **Full-stack web development** with modern technologies
- **Cybersecurity concepts** and threat analysis
- **User experience design** with interactive elements
- **Educational technology** integration
- **Security-first development** practices

Perfect for showcasing technical skills while contributing to cybersecurity education and awareness.

---

This project is released under the MIT License. See the LICENSE file for details.

## 🚀 Deploy Your Project Live

### Quick Deployment Options

#### Option 1: Render.com (Recommended)
1. Push your code to GitHub
2. Visit [https://render.com](https://render.com) and connect GitHub
3. Create "New Web Service" and select your repository
4. Use settings: Build: `pip install -r requirements.txt`, Start: `gunicorn app:app`
5. Deploy! Your app will be live at `https://your-app-name.onrender.com`

#### Option 2: Railway.app
1. Visit [https://railway.app](https://railway.app)
2. Connect GitHub repository
3. One-click deployment!
4. Live at `https://your-app.railway.app`

#### Option 3: Heroku
```bash
heroku create your-app-name
git push heroku main
```

**Your project is deployment-ready with:**
- ✅ Procfile configured
- ✅ requirements.txt prepared  
- ✅ Production settings ready
- ✅ Git repository initialized

See `DEPLOYMENT_GUIDE.md` for detailed instructions!

---

**Happy learning and stay secure! 🛡️**

**Ready to go live? Choose a deployment platform above! 🌐**