# 📋 Complete Commands & Setup Guide

## 🔧 Initial Setup Commands

### 1. Install Prerequisites
```bash
# Download and install Npcap from https://npcap.com
# Make sure to check "Install Npcap in WinPcap API-compatible Mode"
```

### 2. Clone Repository
```bash
git clone https://github.com/syedfasihzaidi480/Wifi-Snipper.git
cd Wifi-Snipper
```

### 3. Setup Python Environment
```bash
# Automatic setup (Windows)
setup.bat

# Manual setup
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## 🚀 Running Commands

### Main Scanner (Recommended)
```bash
# Open PowerShell as Administrator
# Navigate to project folder
cd "C:\path\to\Wifi-Snipper"

# Activate environment
.venv\Scripts\activate

# Run main scanner
python advanced_network_scanner.py
```

### All Available Scripts
```bash
# Complete network scanner (MAIN)
python advanced_network_scanner.py

# Enhanced device scanner with menu
python monitor_all.py

# Simple device discovery
python simple_scanner.py  

# WiFi monitor with browsing detection
python wifi_monitor.py

# Browsing activity sniffer
python "from scapy.py"

# Test packet capture capability
python test_capture.py
```

## 📊 Scanner Menu Options

### Advanced Network Scanner Menu
```
1. 🔍 Full Network Discovery Scan
   - Finds ALL devices using 5 methods
   - ARP scan, ping sweep, service detection
   - Device name resolution
   
2. 🎥 CCTV Camera Scanner  
   - Searches for security cameras
   - Tests camera web interfaces
   - Finds Hikvision, Dahua, Axis cameras
   
3. 📊 Show Last Scan Results
   - Complete device list with details
   - CCTV cameras found
   - Web services discovered
   
4. 📡 Monitor Your Traffic
   - Real-time traffic monitoring
   - DNS queries and web activity
   - HTTPS/HTTP connections
   
5. 📚 Explain Technical Limitations
   - What's possible vs impossible
   - Network monitoring constraints
   - Legal and technical barriers
```

## 🎯 Step-by-Step Usage

### For Complete Network Analysis:
```bash
# Step 1: Test setup
python test_capture.py

# Step 2: Run comprehensive scan
python advanced_network_scanner.py
# Choose: 1 (Full Network Discovery)

# Step 3: Find CCTV cameras
# Choose: 2 (CCTV Scanner)

# Step 4: View all results
# Choose: 3 (Show Results)

# Step 5: Monitor live traffic
# Choose: 4 (Monitor Traffic)
```

### For Quick Device Discovery:
```bash
python simple_scanner.py
# Choose: 1 (Scan for devices)
```

### For Traffic Monitoring Only:
```bash
python monitor_all.py
# Choose: 1 (Scan devices first)
# Choose: 2 (Monitor traffic)
```

## 🔧 Troubleshooting Commands

### Check Administrator Status
```bash
whoami /priv
```

### Test Network Connectivity
```bash
ping 192.168.1.1
ipconfig /all
arp -a
```

### Check Python Environment
```bash
python --version
pip list
```

### Test Scapy Installation
```bash
python -c "from scapy.all import *; print('Scapy working!')"
```

### Check Available Network Interfaces
```bash
python -c "from scapy.all import get_if_list; print('\n'.join(get_if_list()))"
```

### Test Packet Capture
```bash
# Quick test
python test_capture.py

# Manual test
python -c "from scapy.all import sniff; sniff(count=1, timeout=5)"
```

## 🌐 Git Commands for Pushing to GitHub

### Initial Push
```bash
# Initialize git repository
git init

# Add all files
git add .

# Commit changes
git commit -m "Initial commit: WiFi Network Scanner project"

# Add remote repository
git remote add origin https://github.com/syedfasihzaidi480/Wifi-Snipper.git

# Push to GitHub
git push -u origin main
```

### Update Repository
```bash
# Add new changes
git add .

# Commit with message
git commit -m "Update: Added new features and documentation"

# Push changes
git push origin main
```

### Create New Branch for Features
```bash
# Create and switch to new branch
git checkout -b feature/new-scanner

# Make changes, then add and commit
git add .
git commit -m "Add new scanning feature"

# Push branch
git push origin feature/new-scanner

# Merge to main (on GitHub or locally)
git checkout main
git merge feature/new-scanner
git push origin main
```

## 📱 Network Interface Selection Guide

### Identify Your WiFi Interface
```bash
# List all interfaces
python -c "from scapy.all import get_if_list; [print(f'{i+1}. {iface}') for i, iface in enumerate(get_if_list())]"

# Common interface patterns:
# WiFi: Usually contains "802.11" or your WiFi adapter name
# Ethernet: Usually first in list
# VPN: May contain "TAP" or VPN software name
# Loopback: Contains "Loopback" - skip this
```

### Interface Selection Tips
- **Interface #1-3**: Usually main network adapters
- **Look for**: WiFi adapter, 802.11, your network card name
- **Avoid**: Loopback, VPN adapters, virtual interfaces
- **Test**: If unsure, try interface #1, then #2, then #3

## 🎥 CCTV Camera Access

### Common Camera Ports
```
Port 80   - HTTP web interface
Port 554  - RTSP video stream
Port 8080 - Alternative HTTP
Port 37777- Dahua cameras
Port 34567- Hikvision cameras
```

### Camera Web Interface URLs
```
# Standard HTTP
http://192.168.1.xxx

# Alternative ports
http://192.168.1.xxx:8080
http://192.168.1.xxx:9000

# Default login (try these):
admin/admin
admin/password
admin/12345
admin/(blank)
```

## 📊 Expected Results Examples

### Device Discovery
```
Found 23 devices:
- 192.168.1.1 (Router)
- 192.168.1.60 (Your PC)
- 192.168.1.37 (Another Computer)
- 192.168.1.104 (Security Camera)
- 192.168.1.15 (Phone)
- etc.
```

### CCTV Detection
```
🎥 CCTV Cameras Found:
- http://192.168.1.104 (Dahua Camera)
- http://192.168.1.150:8080 (Hikvision NVR)
```

### Traffic Monitoring
```
[11:30:15] DNS: github.com
[11:30:16] HTTPS: github.com:443
[11:30:20] DNS: google.com
[11:30:21] HTTPS: google.com:443
```

## 🔒 Important Security Notes

### Run as Administrator
```bash
# Right-click PowerShell
# Select "Run as administrator"
# Navigate to project folder
# Run scripts
```

### Firewall Considerations
- Windows Firewall may block packet capture
- Antivirus may flag network scanning
- Corporate networks may have restrictions

### Legal Usage Only
- Only scan networks you own/manage
- Get authorization for security testing
- Respect privacy and local laws
- Don't use for unauthorized access

## 🚀 Performance Tips

### For Maximum Device Discovery
1. Run as Administrator
2. Disable VPN temporarily
3. Use main WiFi interface
4. Wait for complete scans (30+ seconds)
5. Try multiple scan types

### For Best CCTV Detection
1. Use option 2 (CCTV Scanner)
2. Wait for port scanning completion
3. Check common IP ranges manually
4. Look for devices with HTTP ports open

### For Reliable Traffic Monitoring
1. Choose correct network interface
2. Generate traffic while monitoring
3. Use option 4 (Monitor Your Traffic)
4. Monitor DNS queries for web activity