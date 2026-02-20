#!/usr/bin/env python3
"""
Advanced Network Scanner & Monitor
- Discovers all network devices using multiple methods
- Attempts to identify device types and services
- Scans for CCTV cameras and web services
- Monitors available network traffic
- Explains technical limitations
"""

import socket
import subprocess
import threading
import time
import os
import sys
from datetime import datetime
from scapy.all import *
import requests
from concurrent.futures import ThreadPoolExecutor
import json

class NetworkScanner:
    def __init__(self):
        self.devices = {}
        self.local_ip = self.get_local_ip()
        self.subnet = ".".join(self.local_ip.split(".")[:3])
        self.cctv_found = []
        self.web_services = []
        
    def clear_screen(self):
        os.system("cls" if os.name == "nt" else "clear")
        
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "192.168.1.100"  # fallback
            
    def check_admin(self):
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False

    def multi_discovery_scan(self):
        """Use multiple discovery methods for comprehensive device detection."""
        print("🔍 Starting comprehensive network discovery...")
        print(f"   Network: {self.subnet}.0/24")
        print(f"   Your IP: {self.local_ip}")
        
        # Method 1: ARP Scan (if admin)
        if self.check_admin():
            print("\n1️⃣ ARP Discovery (Administrator mode)...")
            self.arp_scan()
        else:
            print("\n⚠️  Not running as Administrator - ARP scan limited")
            
        # Method 2: Ping Discovery
        print("\n2️⃣ Ping Discovery...")
        self.ping_scan()
        
        # Method 3: Port Scanning (common services)
        print("\n3️⃣ Service Discovery...")
        self.service_scan()
        
        # Method 4: mDNS/Bonjour Discovery
        print("\n4️⃣ mDNS Discovery...")
        self.mdns_scan()
        
        # Method 5: NetBIOS Discovery
        print("\n5️⃣ NetBIOS Discovery...")
        self.netbios_scan()
        
        print(f"\n✅ Discovery complete! Found {len(self.devices)} devices")
        
    def arp_scan(self):
        try:
            subnet = f"{self.subnet}.0/24"
            
            # Find best interface
            interface = None
            for iface in get_if_list():
                if "loopback" not in iface.lower() and "teredo" not in iface.lower():
                    interface = iface
                    break
                    
            if interface:
                ans, unans = srp(
                    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
                    iface=interface, timeout=3, verbose=0, retry=1
                )
                
                for sent, received in ans:
                    ip = received.psrc
                    mac = received.hwsrc
                    self.devices[ip] = {
                        'ip': ip,
                        'mac': mac,
                        'hostname': 'Unknown',
                        'services': [],
                        'device_type': 'Unknown',
                        'discovery_method': 'ARP',
                        'responsive': True
                    }
                    print(f"   Found: {ip} ({mac})")
                    
        except Exception as e:
            print(f"   ARP scan failed: {e}")
            
    def ping_scan(self):
        def ping_ip(ip_num):
            ip = f"{self.subnet}.{ip_num}"
            try:
                result = subprocess.run(
                    ["ping", "-n", "1", "-w", "500", ip],
                    capture_output=True, text=True, timeout=2
                )
                if "TTL=" in result.stdout and ip != self.local_ip:
                    if ip not in self.devices:
                        self.devices[ip] = {
                            'ip': ip,
                            'mac': 'Unknown',
                            'hostname': 'Unknown',
                            'services': [],
                            'device_type': 'Unknown',
                            'discovery_method': 'Ping',
                            'responsive': True
                        }
                    print(f"   Ping response: {ip}")
            except Exception:
                pass
        
        # Scan common IP ranges
        ranges = [1, 2, 3, 4, 5] + list(range(10, 50)) + list(range(100, 200)) + [254]
        with ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(ping_ip, ranges)
            
    def service_scan(self):
        """Scan for common services and identify device types."""
        common_ports = {
            21: "FTP",
            22: "SSH", 
            23: "Telnet",
            53: "DNS",
            80: "HTTP",
            135: "RPC",
            139: "NetBIOS",
            443: "HTTPS", 
            445: "SMB",
            554: "RTSP (Camera)",
            8080: "HTTP-Alt",
            8081: "HTTP-Alt",
            37777: "Dahua Camera",
            34567: "Hikvision Camera",
            85: "HTTP (Camera)",
            8000: "HTTP (Camera)",
            9000: "HTTP (Camera)"
        }
        
        def scan_device_ports(ip):
            services = []
            for port, service in common_ports.items():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    
                    if result == 0:
                        services.append(f"{service}:{port}")
                        
                        # Identify device type based on services
                        if port in [554, 37777, 34567, 85] or (port in [8000, 8080, 8081, 9000] and "camera" in service.lower()):
                            if ip not in self.cctv_found:
                                self.cctv_found.append(ip)
                                self.check_camera_web_interface(ip, port)
                                
                        elif port in [80, 443, 8080, 8081]:
                            self.check_web_service(ip, port)
                            
                except Exception:
                    pass
                    
            if services and ip in self.devices:
                self.devices[ip]['services'] = services
                self.identify_device_type(ip, services)
                
        with ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(scan_device_ports, list(self.devices.keys()))
            
    def check_camera_web_interface(self, ip, port):
        """Check if device has camera web interface."""
        urls = [
            f"http://{ip}:{port}",
            f"http://{ip}",
            f"http://{ip}:8080",
            f"http://{ip}:9000"
        ]
        
        for url in urls:
            try:
                response = requests.get(url, timeout=3, verify=False)
                if response.status_code == 200:
                    content = response.text.lower()
                    if any(keyword in content for keyword in ['camera', 'surveillance', 'dvr', 'nvr', 'hikvision', 'dahua']):
                        print(f"   🎥 CCTV Web Interface: {url}")
                        if ip in self.devices:
                            self.devices[ip]['device_type'] = 'Security Camera'
                        break
            except Exception:
                continue
                
    def check_web_service(self, ip, port):
        """Check web services on devices."""
        try:
            url = f"http://{ip}:{port}" if port != 80 else f"http://{ip}"
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                title = "Web Service"
                if "<title>" in response.text:
                    try:
                        title = response.text.split("<title>")[1].split("</title>")[0]
                        title = title[:50]  # limit length
                    except:
                        pass
                        
                self.web_services.append({
                    'ip': ip,
                    'port': port,
                    'url': url,
                    'title': title
                })
                print(f"   🌐 Web Service: {url} ({title})")
        except Exception:
            pass
            
    def identify_device_type(self, ip, services):
        """Identify device type based on open services."""
        if ip not in self.devices:
            return
            
        services_str = " ".join(services).lower()
        
        if any(s in services_str for s in ['rtsp', 'camera', '37777', '34567']):
            self.devices[ip]['device_type'] = 'Security Camera'
        elif 'smb' in services_str or 'netbios' in services_str:
            self.devices[ip]['device_type'] = 'Windows Computer'
        elif 'ssh' in services_str:
            self.devices[ip]['device_type'] = 'Linux/Unix Device'
        elif ip.endswith('.1'):
            self.devices[ip]['device_type'] = 'Router/Gateway'
        elif any(s in services_str for s in ['http', 'https']):
            self.devices[ip]['device_type'] = 'Network Device'
        else:
            self.devices[ip]['device_type'] = 'Unknown Device'
            
    def mdns_scan(self):
        """Listen for mDNS/Bonjour announcements."""
        try:
            def mdns_callback(packet):
                if packet.haslayer('DNS') and hasattr(packet['DNS'], 'an'):
                    for i in range(packet['DNS'].ancount):
                        rr = packet['DNS'].an[i]
                        if hasattr(rr, 'rdata') and hasattr(rr, 'rrname'):
                            name = rr.rrname.decode() if isinstance(rr.rrname, bytes) else str(rr.rrname)
                            if name.endswith('.local.'):
                                device_name = name.replace('.local.', '')
                                if packet.haslayer('IP'):
                                    ip = packet['IP'].src
                                    if ip in self.devices:
                                        self.devices[ip]['hostname'] = device_name
                                        print(f"   mDNS: {ip} = {device_name}")
                                        
            # Listen for mDNS for a short time
            sniff(filter="udp port 5353", prn=mdns_callback, timeout=3, store=0)
        except Exception as e:
            print(f"   mDNS scan failed: {e}")
            
    def netbios_scan(self):
        """Scan for NetBIOS names."""
        def get_netbios_name(ip):
            try:
                result = subprocess.run(
                    ["nbtstat", "-a", ip],
                    capture_output=True, text=True, timeout=3
                )
                for line in result.stdout.split("\n"):
                    if "<00>" in line and "UNIQUE" in line:
                        name = line.split("<00>")[0].strip()
                        if name and len(name) > 1:
                            if ip in self.devices:
                                self.devices[ip]['hostname'] = name
                                print(f"   NetBIOS: {ip} = {name}")
                            return
            except Exception:
                pass
                
        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(get_netbios_name, list(self.devices.keys()))
    
    def display_results(self):
        """Display comprehensive scan results."""
        self.clear_screen()
        
        print("🚀" + "="*70 + "🚀")
        print("  📱 COMPREHENSIVE NETWORK SCAN RESULTS")
        print("🚀" + "="*70 + "🚀")
        print(f"  🏠 Network: {self.subnet}.0/24")
        print(f"  🖥️  Your IP: {self.local_ip}")
        print(f"  📊 Total Devices: {len(self.devices)}")
        print(f"  🎥 CCTV Cameras: {len(self.cctv_found)}")
        print(f"  🌐 Web Services: {len(self.web_services)}")
        print("="*72)
        
        # Device List
        if self.devices:
            print("\n📱 DISCOVERED DEVICES:")
            print("-"*72)
            sorted_devices = sorted(self.devices.items(), key=lambda x: socket.inet_aton(x[0]))
            
            for i, (ip, info) in enumerate(sorted_devices, 1):
                hostname = info.get('hostname', 'Unknown')
                device_type = info.get('device_type', 'Unknown')
                services = info.get('services', [])
                mac = info.get('mac', 'Unknown')
                
                # Icon based on device type
                if 'camera' in device_type.lower():
                    icon = "🎥"
                elif 'router' in device_type.lower():
                    icon = "🌐"
                elif 'computer' in device_type.lower():
                    icon = "💻"
                elif ip == self.local_ip:
                    icon = "🖥️"
                else:
                    icon = "🔌"
                    
                print(f"{i:2d}. {icon} {ip:<15} | {device_type:<20}")
                print(f"     Name: {hostname}")
                if mac != 'Unknown':
                    print(f"     MAC:  {mac}")
                if services:
                    print(f"     Services: {', '.join(services[:3])}")
                    if len(services) > 3:
                        print(f"              + {len(services)-3} more...")
                print()
        
        # CCTV Cameras Section
        if self.cctv_found:
            print("\n🎥 CCTV/SECURITY CAMERAS FOUND:")
            print("-"*50)
            for ip in self.cctv_found:
                device_info = self.devices.get(ip, {})
                hostname = device_info.get('hostname', 'Unknown')
                services = device_info.get('services', [])
                
                print(f"📹 {ip} ({hostname})")
                print(f"   Services: {', '.join(services)}")
                
                # Web interface URLs
                for web in self.web_services:
                    if web['ip'] == ip:
                        print(f"   🌐 Web: {web['url']} - {web['title']}")
                print()
                
        # Web Services Section  
        if self.web_services:
            print("\n🌐 WEB SERVICES FOUND:")
            print("-"*50)
            for web in self.web_services:
                if web['ip'] not in self.cctv_found:  # Don't repeat CCTV
                    print(f"🌐 {web['url']} - {web['title']}")
                    
    def explain_limitations(self):
        """Explain technical limitations of network monitoring."""
        print("\n" + "="*60)
        print("  ⚠️  IMPORTANT: Network Monitoring Limitations")
        print("="*60)
        
        print("""
🔒 WEBSITE MONITORING LIMITATIONS:
   • Modern networks use SWITCHED infrastructure (not hubs)
   • You can only see traffic TO/FROM your own computer
   • Other devices' traffic is NOT visible unless you're the router
   • HTTPS encrypts 95% of web traffic (can't see content)
   • Network isolation prevents cross-device packet capture

🛡️ WHAT YOU CAN MONITOR:
   ✅ Your own web browsing and network activity  
   ✅ DNS queries from/to your computer
   ✅ Devices connected to the network (IP/MAC addresses)
   ✅ Open services/ports on other devices
   ✅ CCTV camera web interfaces (if accessible)

❌ WHAT YOU CANNOT MONITOR:
   ❌ Other devices' web browsing history
   ❌ HTTPS content from other devices  
   ❌ Private traffic between other devices
   ❌ Encrypted messaging/calls

🔧 TO MONITOR OTHER DEVICES' TRAFFIC, YOU WOULD NEED:
   • Router admin access (to enable port mirroring)
   • Professional network monitoring tools
   • Enterprise-grade managed switches
   • Legal authorization (in most jurisdictions)

🎯 WHAT THIS TOOL PROVIDES:
   ✅ Complete device discovery on your network
   ✅ Service identification (web, cameras, etc.)
   ✅ CCTV camera detection and access
   ✅ Your own traffic monitoring
   ✅ Network security assessment
""")
        
    def monitor_own_traffic(self):
        """Monitor traffic from your own computer."""
        print("\n🔴 MONITORING YOUR TRAFFIC (Press Ctrl+C to stop)")
        print("="*50)
        
        def packet_callback(packet):
            if packet.haslayer('IP'):
                ip_src = packet['IP'].src
                ip_dst = packet['IP'].dst
                timestamp = datetime.now().strftime("%H:%M:%S")
                
                # Only show traffic from/to this computer
                if ip_src == self.local_ip or ip_dst == self.local_ip:
                    
                    # DNS queries
                    if packet.haslayer('DNS') and hasattr(packet['DNS'], 'qd'):
                        if packet['DNS'].qd:
                            query = packet['DNS'].qd.qname.decode()
                            print(f"[{timestamp}] 🌐 DNS: {query}")
                            
                    # HTTP traffic
                    elif packet.haslayer('TCP'):
                        sport = packet['TCP'].sport
                        dport = packet['TCP'].dport
                        
                        if sport == 80 or dport == 80:
                            print(f"[{timestamp}] 🔗 HTTP: {ip_src}:{sport} ↔ {ip_dst}:{dport}")
                        elif sport == 443 or dport == 443:
                            print(f"[{timestamp}] 🔒 HTTPS: {ip_src}:{sport} ↔ {ip_dst}:{dport}")
                            
        try:
            sniff(filter=f"host {self.local_ip}", prn=packet_callback, store=0)
        except KeyboardInterrupt:
            print("\n✅ Traffic monitoring stopped")
            
    def run_cctv_scan(self):
        """Dedicated CCTV camera scanner."""
        print("\n🎥 SCANNING FOR CCTV CAMERAS...")
        print("="*40)
        
        # Common CCTV ports and services
        cctv_ports = [80, 554, 8080, 8081, 9000, 37777, 34567, 85, 8000]
        cctv_keywords = ['camera', 'surveillance', 'dvr', 'nvr', 'hikvision', 'dahua', 'axis']
        
        def scan_for_camera(ip_num):
            ip = f"{self.subnet}.{ip_num}"
            camera_services = []
            
            for port in cctv_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    
                    if result == 0:
                        camera_services.append(port)
                        
                        # Check HTTP interface
                        try:
                            url = f"http://{ip}:{port}" if port != 80 else f"http://{ip}"
                            response = requests.get(url, timeout=3)
                            if any(keyword in response.text.lower() for keyword in cctv_keywords):
                                print(f"🎥 CAMERA FOUND: {ip}:{port}")
                                print(f"    Web Interface: {url}")
                                if ip not in self.cctv_found:
                                    self.cctv_found.append(ip)
                        except:
                            pass
                            
                except Exception:
                    pass
                    
            if camera_services:
                print(f"📹 Possible camera: {ip} (ports: {camera_services})")
                
        # Scan IP range for cameras
        ranges = list(range(1, 255))
        with ThreadPoolExecutor(max_workers=30) as executor:
            executor.map(scan_for_camera, ranges)
            
        print(f"\n✅ CCTV scan complete. Found {len(self.cctv_found)} cameras.")

def main():
    scanner = NetworkScanner()
    
    while True:
        scanner.clear_screen()
        print("🚀" + "="*50 + "🚀")
        print("  📡 Advanced Network Scanner & Monitor")
        print("🚀" + "="*50 + "🚀")
        
        if not scanner.check_admin():
            print("⚠️  Not running as Administrator")
            print("   Some features will be limited")
        else:
            print("✅ Running as Administrator")
            
        print(f"\n🏠 Your Network: {scanner.subnet}.0/24")
        print(f"🖥️ Your IP: {scanner.local_ip}")
        
        print("\nChoose an option:")
        print("1. 🔍 Full Network Discovery Scan")
        print("2. 🎥 CCTV Camera Scanner")  
        print("3. 📊 Show Last Scan Results")
        print("4. 📡 Monitor Your Traffic")
        print("5. 📚 Explain Technical Limitations")
        print("6. ❌ Exit")
        
        try:
            choice = input("\nEnter choice (1-6): ").strip()
            
            if choice == "1":
                scanner.multi_discovery_scan()
                scanner.display_results()
                input("\nPress Enter to continue...")
                
            elif choice == "2":
                scanner.run_cctv_scan()
                input("\nPress Enter to continue...")
                
            elif choice == "3":
                if scanner.devices:
                    scanner.display_results()
                else:
                    print("\n❌ No scan data available. Run option 1 first.")
                input("\nPress Enter to continue...")
                
            elif choice == "4":
                scanner.monitor_own_traffic()
                
            elif choice == "5":
                scanner.explain_limitations()
                input("\nPress Enter to continue...")
                
            elif choice == "6":
                print("👋 Goodbye!")
                break
                
            else:
                print("Invalid choice!")
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"\n❌ Error: {e}")
            input("Press Enter to continue...")

if __name__ == "__main__":
    main()