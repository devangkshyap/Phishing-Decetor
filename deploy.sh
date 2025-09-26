#!/bin/bash
# Quick Deployment Script for Cybersecurity Platform

echo "🚀 Deploying Cybersecurity Platform..."

# Step 1: Initialize Git (if not already done)
if [ ! -d ".git" ]; then
    echo "📁 Initializing Git repository..."
    git init
fi

# Step 2: Add all files
echo "📦 Adding files to Git..."
git add .

# Step 3: Commit changes
echo "💾 Committing changes..."
git commit -m "Deploy cybersecurity platform - $(date)"

# Step 4: Instructions for deployment platforms
echo ""
echo "✅ Your project is ready for deployment!"
echo ""
echo "🌐 Choose a deployment platform:"
echo ""
echo "1️⃣  RENDER.COM (Recommended)"
echo "   - Go to https://render.com"
echo "   - Sign up and connect GitHub"
echo "   - Create new Web Service"
echo "   - Select your repository"
echo "   - Deploy automatically!"
echo ""
echo "2️⃣  RAILWAY.APP"
echo "   - Go to https://railway.app"
echo "   - Connect GitHub repository"
echo "   - One-click deployment"
echo ""
echo "3️⃣  HEROKU"
echo "   - Install Heroku CLI"
echo "   - Run: heroku create your-app-name"
echo "   - Run: git push heroku main"
echo ""
echo "📋 Your project includes:"
echo "   ✅ Procfile for deployment"
echo "   ✅ requirements.txt for dependencies"
echo "   ✅ Production-ready configuration"
echo "   ✅ Environment variables template"
echo ""
echo "🔗 After deployment, your platform will be live at:"
echo "   https://your-app-name.platform.com"
echo ""
echo "Happy deploying! 🎉"