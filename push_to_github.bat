@echo off
echo 🚀 Pushing WiFi Snipper Project to GitHub
echo ==========================================

echo Initializing git repository...
git init

echo Adding all files...
git add .

echo Creating initial commit...
git commit -m "Initial commit: Complete WiFi Network Scanner project with documentation"

echo Adding remote repository...
git remote add origin https://github.com/syedfasihzaidi480/Wifi-Snipper.git

echo Pushing to GitHub...
git push -u origin main

echo ✅ Project successfully pushed to GitHub!
echo.
echo Repository: https://github.com/syedfasihzaidi480/Wifi-Snipper
echo.
pause