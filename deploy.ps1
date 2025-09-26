# PowerShell Deployment Script for Windows
Write-Host "🚀 Preparing Cybersecurity Platform for Deployment..." -ForegroundColor Green

# Check if Git is initialized
if (-not (Test-Path ".git")) {
    Write-Host "📁 Initializing Git repository..." -ForegroundColor Yellow
    git init
}

# Add files to Git
Write-Host "📦 Adding files to Git..." -ForegroundColor Yellow
git add .

# Commit changes
$commitMessage = "Deploy cybersecurity platform - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "💾 Committing changes..." -ForegroundColor Yellow
git commit -m $commitMessage

Write-Host ""
Write-Host "✅ Your project is ready for deployment!" -ForegroundColor Green
Write-Host ""
Write-Host "🌐 Choose a deployment platform:" -ForegroundColor Cyan
Write-Host ""
Write-Host "1️⃣  RENDER.COM (Recommended)" -ForegroundColor White
Write-Host "   - Go to https://render.com"
Write-Host "   - Sign up and connect GitHub"
Write-Host "   - Create new Web Service"
Write-Host "   - Select your repository"
Write-Host "   - Deploy automatically!"
Write-Host ""
Write-Host "2️⃣  RAILWAY.APP" -ForegroundColor White
Write-Host "   - Go to https://railway.app"
Write-Host "   - Connect GitHub repository"
Write-Host "   - One-click deployment"
Write-Host ""
Write-Host "3️⃣  HEROKU" -ForegroundColor White
Write-Host "   - Install Heroku CLI"
Write-Host "   - Run: heroku create your-app-name"
Write-Host "   - Run: git push heroku main"
Write-Host ""
Write-Host "📋 Your project includes:" -ForegroundColor Cyan
Write-Host "   ✅ Procfile for deployment"
Write-Host "   ✅ requirements.txt for dependencies"
Write-Host "   ✅ Production-ready configuration"
Write-Host "   ✅ Environment variables template"
Write-Host ""
Write-Host "🔗 After deployment, your platform will be live at:" -ForegroundColor Green
Write-Host "   https://your-app-name.platform.com"
Write-Host ""
Write-Host "Happy deploying! 🎉" -ForegroundColor Green

# Pause to let user read
Read-Host "Press Enter to continue..."