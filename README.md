# 📡 WiFi Network Scanner & Sniffer

A comprehensive Python-based network monitoring tool for discovering WiFi devices, CCTV cameras, and analyzing network traffic.

## 🚀 Features

- **🔍 Network Device Discovery** - Finds all connected WiFi devices using multiple scanning methods
- **🎥 CCTV Camera Detection** - Automatically discovers security cameras with web interfaces
- **📡 Traffic Monitoring** - Real-time network activity monitoring
- **🌐 Service Identification** - Detects web services, file shares, and open ports
- **📱 Device Type Classification** - Identifies computers, phones, cameras, routers, IoT devices
- **🔒 Security Analysis** - Network vulnerability assessment

## 📁 Project Structure

```
WiFi-Snipper/
├── advanced_network_scanner.py   # Complete comprehensive scanner ⭐
├── wifi_monitor.py               # Full device + browsing monitor
├── monitor_all.py                # Enhanced device scanner with menu
├── simple_scanner.py             # Basic device discovery
├── from scapy.py                 # Browsing activity sniffer
├── test_capture.py               # Packet capture test
├── requirements.txt              # Python dependencies
├── setup.bat                     # Windows setup script
└── README.md                     # This file
```

## ⚡ Quick Start

### 1. Prerequisites
- **Windows 10/11**
- **Python 3.8+**
- **Administrator privileges** (for full functionality)
- **Npcap** - Download from https://npcap.com

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/syedfasihzaidi480/Wifi-Snipper.git
cd Wifi-Snipper

# Run setup script (Windows)
setup.bat

# Or manual setup:
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Usage

#### 🔥 Main Scanner (Recommended)
```bash
# Run as Administrator for best results
python advanced_network_scanner.py
```

**Menu Options:**
1. **🔍 Full Network Discovery** - Find all devices
2. **🎥 CCTV Scanner** - Discover security cameras
3. **📊 Show Results** - Display last scan
4. **📡 Monitor Traffic** - Watch network activity
5. **📚 Technical Limitations** - Understanding network monitoring

#### 📱 Alternative Scanners
```bash
# Enhanced device scanner
python monitor_all.py

# Simple device discovery
python simple_scanner.py

# Browsing activity monitor
python "from scapy.py"

# Complete device + traffic monitor
python wifi_monitor.py

# Test packet capture capability
python test_capture.py
```

## 🎯 Screenshots & Examples

### Device Discovery Results
```
🚀======================================================🚀
  📱 COMPREHENSIVE NETWORK SCAN RESULTS
🚀======================================================🚀
  🏠 Network: 192.168.1.0/24
  🖥️ Your IP: 192.168.1.60
  📊 Total Devices: 23
  🎥 CCTV Cameras: 3
  🌐 Web Services: 8
========================================================

📱 DISCOVERED DEVICES:
 1. 🖥️ 192.168.1.60     | Windows Computer (You)
 2. 🌐 192.168.1.1      | Router/Gateway  
 3. 🎥 192.168.1.104    | Security Camera
 4. 💻 192.168.1.37     | DESKTOP-OUKMVM0
 5. 📱 192.168.1.15     | Android Device
 6. 🍎 192.168.1.25     | iPhone
 7. 🔌 192.168.1.200    | IoT Device
```

### CCTV Camera Detection
```
🎥 CCTV/SECURITY CAMERAS FOUND:
📹 192.168.1.104 (Dahua-Camera)
   Services: HTTP:80, RTSP:554, Camera:37777
   🌐 Web Interface: http://192.168.1.104
   
📹 192.168.1.150 (Hikvision-NVR)
   Services: HTTP:80, RTSP:554
   🌐 Web Interface: http://192.168.1.150:8080
```

### Live Traffic Monitoring
```
🔴 MONITORING YOUR TRAFFIC (Press Ctrl+C to stop)
[11:30:15] 🌐 DNS: github.com
[11:30:15] 🔒 HTTPS: 192.168.1.60 ↔ 140.82.112.4:443
[11:30:20] 🌐 DNS: www.google.com
[11:30:21] 🔒 HTTPS: 192.168.1.60 ↔ 172.217.164.196:443
[11:30:25] 🔗 HTTP: 192.168.1.60 ↔ 192.168.1.104:80
```

## 🔧 Detailed Usage Guide

### Network Discovery Methods
The scanner uses 5 different discovery techniques:

1. **ARP Scanning** (Administrator required)
   - Most comprehensive device discovery
   - Gets MAC addresses and vendors

2. **Ping Sweep**
   - Works without admin privileges
   - Fast IP range scanning

3. **Service/Port Scanning**
   - Identifies device types by open services
   - Detects web interfaces, file shares, cameras

4. **mDNS Discovery**
   - Finds Apple devices and modern IoT
   - Discovers device hostnames

5. **NetBIOS Scanning**
   - Windows device name resolution
   - Network share discovery

### CCTV Camera Features
- **Auto-detection** of security cameras
- **Brand identification** (Hikvision, Dahua, Axis)
- **Web interface access** - Direct links to camera GUIs
- **Port scanning** for common camera services
- **RTSP stream detection**

### Network Interface Selection
```
Available interfaces:
  1. \Device\NPF_{...} - Ethernet
  2. \Device\NPF_{...} - WiFi Adapter ← Usually this one
  3. \Device\NPF_{...} - VPN Interface
  4. \Device\NPF_Loopback - Skip this
```

**Tip:** Interface #2 or #4 is usually your main WiFi adapter.

## ⚠️ Technical Limitations

### What You CAN Monitor:
✅ All devices connected to your network  
✅ Device types, names, and services  
✅ CCTV camera access and streams  
✅ Your own web browsing and traffic  
✅ DNS queries from your computer  
✅ Network security vulnerabilities  

### What You CANNOT Monitor:
❌ Other devices' web browsing history  
❌ HTTPS content from other devices  
❌ Private communications between devices  
❌ Encrypted messaging apps  
❌ Traffic on switched networks (without router access)

### Why These Limitations Exist:
- **Network Switching** - Modern networks use switches, not hubs
- **HTTPS Encryption** - 95% of web traffic is encrypted
- **Network Isolation** - Devices are isolated from each other
- **Legal Restrictions** - Privacy laws prevent traffic interception

## 🛠️ Troubleshooting

### No Devices Found?
```bash
# Check if running as Administrator
whoami /priv

# Test network connectivity
ping 192.168.1.1
ipconfig /all

# Test packet capture
python test_capture.py
```

### Permission Errors?
- **Right-click PowerShell** → "Run as administrator"
- Install **Npcap with WinPcap compatibility**
- Check Windows Firewall settings

### CCTV Cameras Not Detected?
```bash
# Run dedicated camera scan
python advanced_network_scanner.py
# Choose option: 2 (CCTV Scanner)

# Check camera IP ranges
# Common ranges: 192.168.1.100-200, 10.0.0.x
```

### Traffic Monitoring Issues?
- Ensure **Administrator privileges**
- Select correct **network interface** (usually WiFi adapter)
- Check if **VPN is active** (may interfere)

## 🔒 Legal & Ethical Use

**⚠️ IMPORTANT:** This tool is for educational and network administration purposes only.

**Authorized Use:**
- ✅ Your own home/office network
- ✅ Networks you own or manage
- ✅ Authorized security testing
- ✅ Network troubleshooting

**Prohibited Use:**
- ❌ Unauthorized network access
- ❌ Traffic interception without consent
- ❌ Privacy violation
- ❌ Illegal surveillance

**Always ensure you have proper authorization before scanning any network.**

## 📦 Dependencies

- **scapy** - Packet manipulation and capture
- **requests** - HTTP requests for web detection
- **mac-vendor-lookup** - MAC address vendor identification

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙋‍♂️ Support

If you encounter issues:
1. Check the [Troubleshooting](#-troubleshooting) section
2. Ensure you're running as Administrator
3. Verify Npcap installation
4. Open an issue with detailed error messages

## 🌟 Features Roadmap

- [ ] GUI interface
- [ ] Mobile device support
- [ ] Advanced packet analysis
- [ ] Network topology mapping
- [ ] Export results to CSV/JSON
- [ ] Scheduled scanning
- [ ] Email/SMS alerts

---

**Made with ❤️ for network administrators and security enthusiasts**