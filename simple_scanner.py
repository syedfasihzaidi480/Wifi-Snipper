#!/usr/bin/env python3
"""
Simple WiFi Device Scanner
Works with or without Administrator privileges
"""

from scapy.all import *
import socket
import subprocess
import threading
import time
import os
from datetime import datetime

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def check_admin():
    """Check if running as Administrator on Windows."""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def get_local_ip():
    """Get this machine's local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "unknown"

def simple_ping_scan():
    """Simple ping-based network scan that works without admin."""
    local_ip = get_local_ip()
    if local_ip == "unknown":
        return {}
    
    print(f"🔍 Scanning network from your IP: {local_ip}")
    base_ip = ".".join(local_ip.split(".")[:3]) + "."
    devices = {}
    
    # Add this PC first
    devices[local_ip] = {
        'name': 'THIS PC (You)',
        'method': 'local',
        'responsive': True
    }
    
    print("⚡ Quick ping scan (common IPs)...")
    
    def ping_ip(ip_num):
        ip = base_ip + str(ip_num)
        try:
            # Use Windows ping command
            result = subprocess.run(
                ["ping", "-n", "1", "-w", "500", ip],
                capture_output=True, 
                text=True, 
                timeout=2
            )
            if "TTL=" in result.stdout and "Request timed out" not in result.stdout:
                # Try to get hostname
                try:
                    hostname = socket.gethostbyaddr(ip)[0].split('.')[0]
                except:
                    hostname = f"Device-{ip.split('.')[-1]}"
                
                devices[ip] = {
                    'name': hostname,
                    'method': 'ping',
                    'responsive': True
                }
                print(f"  ✅ Found: {ip} ({hostname})")
        except:
            pass
    
    # Scan common IP ranges
    common_ips = [1, 2, 3, 4, 5] + list(range(10, 50)) + list(range(100, 150)) + [254]
    
    threads = []
    for ip_num in common_ips:
        if f"{base_ip}{ip_num}" != local_ip:  # Skip our own IP
            t = threading.Thread(target=ping_ip, args=(ip_num,))
            t.daemon = True 
            t.start()
            threads.append(t)
    
    # Wait for all pings to complete (max 3 seconds)
    start_time = time.time()
    for t in threads:
        remaining_time = max(0, 3 - (time.time() - start_time))
        t.join(timeout=remaining_time)
    
    return devices

def advanced_arp_scan():
    """Advanced ARP scan (requires Administrator)."""
    local_ip = get_local_ip()
    if local_ip == "unknown":
        return {}
    
    subnet = ".".join(local_ip.split(".")[:3]) + ".0/24"
    print(f"🚀 Advanced ARP scan: {subnet}")
    
    devices = {}
    
    try:
        # Find best interface
        interface = None
        for i, iface in enumerate(get_if_list()):
            if "loopback" not in iface.lower() and "teredo" not in iface.lower():
                interface = iface
                print(f"   Using interface: {iface}")
                break
        
        if interface:
            print("   Sending ARP requests...")
            ans, unans = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
                iface=interface, 
                timeout=3, 
                verbose=0,
                retry=1
            )
            
            for sent, received in ans:
                ip = received.psrc
                mac = received.hwsrc
                
                # Try to get hostname
                try:
                    hostname = socket.gethostbyaddr(ip)[0].split('.')[0]
                except:
                    hostname = f"Device-{ip.split('.')[-1]}"
                
                devices[ip] = {
                    'name': hostname,
                    'mac': mac,
                    'method': 'arp',
                    'responsive': True
                }
                print(f"  ✅ Found: {ip} ({hostname}) - {mac}")
                
    except Exception as e:
        print(f"   ❌ ARP scan failed: {e}")
        return {}
    
    return devices

def display_devices(devices):
    """Display found devices in a nice table."""
    clear_screen()
    
    print("=" * 80)
    print("  📱 WiFi Connected Devices Scanner")  
    print("=" * 80)
    print(f"  🏠 Your Network: {get_local_ip()}")
    print(f"  ⏰ Scan Time: {datetime.now().strftime('%H:%M:%S')}")
    print(f"  📊 Devices Found: {len(devices)}")
    print("=" * 80)
    
    if not devices:
        print("  ❌ No devices found!")
        print("     Try running as Administrator for better results.")
        return
    
    # Sort by IP
    sorted_devices = sorted(devices.items(), key=lambda x: socket.inet_aton(x[0]))
    
    print(f"{'#':<3} {'IP Address':<16} {'Device Name':<25} {'Status':<15}")
    print("-" * 80)
    
    for i, (ip, info) in enumerate(sorted_devices, 1):
        name = info['name']
        method = info.get('method', 'unknown')
        
        # Add icons
        if ip == get_local_ip():
            name = f"🖥️ {name}"
            status = "YOU"
        elif ip.endswith('.1'):
            name = f"🌐 Router/Gateway"
            status = "GATEWAY"
        elif 'desktop' in name.lower() or 'pc' in name.lower():
            name = f"💻 {name}"
            status = "COMPUTER"
        elif any(x in name.lower() for x in ['phone', 'android', 'iphone']):
            name = f"📱 {name}"
            status = "MOBILE"
        else:
            name = f"🔌 {name}"
            status = "DEVICE"
        
        print(f"{i:<3} {ip:<16} {name:<25} {status:<15}")
    
    print("=" * 80)
    
    # Show scan method used
    methods = set(info.get('method', 'ping') for info in devices.values())
    if 'arp' in methods:
        print("  ✅ Used: Advanced ARP scan (Administrator mode)")
    else:
        print("  ⚡ Used: Simple ping scan (Standard mode)")
        print("  💡 For more devices, run as Administrator")
    
    print("=" * 80)

def test_interfaces():
    """Test which network interface can capture packets."""
    print("\n🔍 Testing network interfaces...")
    print("Available interfaces:")
    
    interfaces = get_if_list()
    working_interfaces = []
    
    for i, iface in enumerate(interfaces, 1):
        print(f"  {i}. {iface}")
        
        # Quick test - try to capture 1 packet 
        try:
            print(f"     Testing... ", end="", flush=True)
            packets = sniff(iface=iface, timeout=1, count=1, store=1)
            if packets:
                print("✅ Working!")
                working_interfaces.append((i, iface))
            else:
                print("⚠️ No traffic")
        except Exception as e:
            print(f"❌ Failed: {str(e)[:30]}...")
    
    print(f"\n💡 Working interfaces: {len(working_interfaces)}")
    return working_interfaces

def main():
    clear_screen()
    
    print("🚀" + "="*60 + "🚀")
    print("  📱 Simple WiFi Device Scanner")
    print("🚀" + "="*60 + "🚀")
    
    # Check admin status
    is_admin = check_admin()
    if is_admin:
        print("  ✅ Running as Administrator - Full features available!")
    else:
        print("  ⚠️  Running as Standard User - Limited scanning")
        print("     For best results: Right-click PowerShell → 'Run as Administrator'")
    
    print("\nChoose what to do:")
    print("  1. 📱 Scan for connected devices")
    print("  2. 🔧 Test network interfaces") 
    print("  3. 📡 Monitor live traffic")
    print("  4. ❌ Exit")
    
    try:
        choice = input("\nEnter choice (1-4): ").strip()
        
        if choice == "1":
            print("\n" + "="*50)
            if is_admin:
                print("🚀 Running advanced device scan...")
                devices = advanced_arp_scan()
                if not devices:
                    print("   ARP scan failed, trying ping scan...")
                    devices = simple_ping_scan()
            else:
                print("⚡ Running simple device scan...")
                devices = simple_ping_scan()
            
            display_devices(devices)
            input("\nPress Enter to continue...")
            
        elif choice == "2":
            working = test_interfaces()
            if working:
                print(f"\n✅ Found {len(working)} working interfaces")
                print("💡 Use these interface numbers for traffic monitoring")
            else:
                print("\n❌ No working interfaces found")
                print("   Try running as Administrator")
            input("\nPress Enter to continue...")
            
        elif choice == "3":
            print("\n📡 Starting traffic monitor...")
            print("Choose interface number from the list above:")
            
            interfaces = get_if_list()
            for i, iface in enumerate(interfaces, 1):
                print(f"  {i}. {iface}")
            
            try:
                iface_num = int(input("Interface number: "))
                if 1 <= iface_num <= len(interfaces):
                    interface = interfaces[iface_num - 1]
                    print(f"\n🎯 Monitoring: {interface}")
                    print("Press Ctrl+C to stop...\n")
                    
                    def packet_handler(pkt):
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        if pkt.haslayer('IP'):
                            src = pkt['IP'].src
                            dst = pkt['IP'].dst
                            print(f"[{timestamp}] {src} → {dst}")
                    
                    sniff(iface=interface, prn=packet_handler, store=0)
                else:
                    print("Invalid interface number")
            except (ValueError, KeyboardInterrupt):
                print("\nStopped.")
            except Exception as e:
                print(f"Error: {e}")
            
        elif choice == "4":
            print("👋 Goodbye!")
            return
        else:
            print("Invalid choice!")
            
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        print(f"\n❌ Error: {e}")

if __name__ == "__main__":
    while True:
        try:
            main()
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"\n❌ Unexpected error: {e}")
            input("Press Enter to continue...")