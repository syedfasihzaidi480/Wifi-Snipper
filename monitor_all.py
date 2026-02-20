from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, get_if_list, srp, ARP, Ether, conf
from collections import defaultdict
from datetime import datetime
import sys
import socket
import subprocess
import threading
import time
import os

# Track activity per interface and devices
interface_activity = defaultdict(int)
connected_devices = {}

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

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

def get_device_name(ip):
    """Try to get device name via nbtstat or DNS lookup."""
    try:
        # Try Windows nbtstat first
        result = subprocess.run(
            ["nbtstat", "-a", ip],
            capture_output=True, text=True, timeout=2
        )
        for line in result.stdout.split("\n"):
            line = line.strip()
            if "<00>" in line and "UNIQUE" in line:
                name = line.split("<00>")[0].strip()
                if name and len(name) > 1:
                    return name
    except Exception:
        pass
    
    try:
        # Try DNS reverse lookup
        name = socket.gethostbyaddr(ip)[0]
        return name.split('.')[0]  # Just the hostname part
    except Exception:
        pass
    
    return "Unknown Device"

def scan_network():
    """Scan the local network for connected devices."""
    local_ip = get_local_ip()
    if local_ip == "unknown":
        print("❌ Could not determine local IP")
        return {}
    
    subnet = ".".join(local_ip.split(".")[:3]) + ".0/24"
    print(f"🔍 Scanning network: {subnet}")
    print(f"   From your IP: {local_ip}")
    
    devices = {}
    
    try:
        # Try to find the best interface for scanning
        print("   Finding network interface...")
        interface = None
        
        # Get all interfaces and try to find one with the local IP
        for iface in get_if_list():
            try:
                # Skip loopback and obvious non-network interfaces
                if any(skip in iface.lower() for skip in ['loopback', 'isatap', 'teredo']):
                    continue
                interface = iface
                print(f"   Trying interface: {iface}")
                break
            except Exception:
                continue
        
        if not interface:
            print("   Using first available interface...")
            interface = get_if_list()[0]
        
        print(f"   Using interface: {interface}")
        
        # Try ARP scan first
        print("   Performing ARP scan...")
        try:
            ans, unans = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
                iface=interface, 
                timeout=5, 
                verbose=0,
                retry=2
            )
            
            print(f"   ARP scan found {len(ans)} responding devices")
            
            for sent, received in ans:
                ip = received.psrc
                mac = received.hwsrc
                devices[ip] = {
                    'mac': mac,
                    'name': 'Resolving...',
                    'last_seen': datetime.now()
                }
                
        except Exception as arp_error:
            print(f"   ARP scan failed: {arp_error}")
            print("   Trying alternative ping sweep...")
            
            # Alternative: ping sweep if ARP fails
            base_ip = ".".join(local_ip.split(".")[:3]) + "."
            
            def ping_host(host_num):
                ip = base_ip + str(host_num)
                try:
                    result = subprocess.run(
                        ["ping", "-n", "1", "-w", "1000", ip],
                        capture_output=True, text=True, timeout=2
                    )
                    if "TTL=" in result.stdout:
                        devices[ip] = {
                            'mac': 'unknown',
                            'name': 'Resolving...',
                            'last_seen': datetime.now()
                        }
                        print(f"   Found: {ip}")
                except Exception:
                    pass
            
            # Ping common IP ranges
            print("   Pinging common device IPs...")
            threads = []
            for i in [1] + list(range(10, 20)) + list(range(100, 110)) + list(range(150, 160)) + [254]:
                t = threading.Thread(target=ping_host, args=(i,))
                t.daemon = True
                t.start()
                threads.append(t)
            
            # Wait for ping results
            for t in threads:
                t.join(timeout=0.5)
        
        # Always add this machine
        if local_ip not in devices:
            devices[local_ip] = {
                'mac': 'this-pc',
                'name': 'THIS PC',
                'last_seen': datetime.now()
            }
        
        print(f"   Found {len(devices)} total devices")
        
        # Resolve names for found devices
        if devices:
            print("   Resolving device names...")
            def resolve_name(ip):
                if ip in devices:
                    if ip == local_ip:
                        devices[ip]['name'] = 'THIS PC'
                    elif ip.endswith('.1'):
                        devices[ip]['name'] = 'Router/Gateway'
                    else:
                        name = get_device_name(ip)
                        devices[ip]['name'] = name
            
            threads = []
            for ip in devices.keys():
                t = threading.Thread(target=resolve_name, args=(ip,))
                t.daemon = True
                t.start()
                threads.append(t)
            
            # Wait up to 3 seconds for name resolution
            for t in threads:
                t.join(timeout=3)
                
        return devices
        
    except Exception as e:
        print(f"❌ Scan error: {e}")
        print(f"   Error details: {type(e).__name__}")
        # Return at least this PC
        return {
            local_ip: {
                'mac': 'this-pc',
                'name': 'THIS PC',
                'last_seen': datetime.now()
            }
        }

def display_devices(devices):
    """Display connected devices in a nice format."""
    clear_screen()
    local_ip = get_local_ip()
    
    print("=" * 70)
    print("  📱 WiFi Connected Devices")
    print("=" * 70)
    print(f"  Your IP: {local_ip}")
    print(f"  Scan Time: {datetime.now().strftime('%H:%M:%S')}")
    print(f"  Devices Found: {len(devices)}")
    print("=" * 70)
    
    if not devices:
        print("  ❌ No devices found.")
        print("     Possible reasons:")
        print("     • Not running as Administrator")
        print("     • WiFi network isolation enabled")
        print("     • Firewall blocking scans")
        print("     • Network interface detection issue")
        print("\n  💡 Try running PowerShell as Administrator")
        return
    
    # Sort devices by IP for consistent display
    try:
        sorted_devices = sorted(devices.items(), key=lambda x: socket.inet_aton(x[0]))
    except:
        sorted_devices = sorted(devices.items())
    
    print(f"{'#':<3} {'IP Address':<16} {'Device Name':<25} {'MAC Address':<18}")
    print("-" * 70)
    
    for i, (ip, info) in enumerate(sorted_devices, 1):
        device_name = info['name']
        mac_addr = info.get('mac', 'unknown')
        
        # Highlight specific device types
        if ip == local_ip:
            device_name = "🖥️  THIS PC"
        elif ip.endswith('.1') or 'router' in device_name.lower() or 'gateway' in device_name.lower():
            device_name = "🌐 Router/Gateway"
        elif 'android' in device_name.lower() or 'samsung' in device_name.lower() or 'galaxy' in device_name.lower():
            device_name = f"📱 {device_name}"
        elif any(x in device_name.lower() for x in ['iphone', 'ipad', 'apple', 'ios']):
            device_name = f"🍎 {device_name}"
        elif any(x in device_name.lower() for x in ['laptop', 'desktop', 'pc', 'computer']):
            device_name = f"💻 {device_name}"
        elif any(x in device_name.lower() for x in ['camera', 'nvr', 'dvr']):
            device_name = f"📷 {device_name}"
        elif any(x in device_name.lower() for x in ['smart', 'iot', 'alexa', 'google']):
            device_name = f"🏠 {device_name}"
        else:
            device_name = f"🔌 {device_name}"
        
        print(f"{i:<3} {ip:<16} {device_name:<25} {mac_addr:<18}")
    
    print("=" * 70)
    
    if len(devices) == 1:
        print("  💡 Only found your PC. This might mean:")
        print("     • Network isolation is enabled (common in public WiFi)")
        print("     • Need Administrator privileges for network scanning")
        print("     • Devices are not responding to network scans")
        print("  🔧 Try: Run as Administrator or use a different network")
    elif len(devices) < 5:
        print("  💡 Found fewer devices than expected?")
        print("     • Some devices may have firewalls blocking discovery")
        print("     • Try running as Administrator for better results")
    
    print("=" * 70)

def show_devices_menu():
    """Show the devices discovery menu."""
    while True:
        print("\n" + "=" * 50)
        print("  📱 WiFi Device Scanner")
        print("=" * 50)
        print("  1. Scan for connected devices")
        print("  2. Monitor network traffic")
        print("  3. Exit")
        print("=" * 50)
        
        try:
            choice = input("  Enter your choice (1-3): ").strip()
            
            if choice == "1":
                print("\n🔍 Scanning for devices...")
                devices = scan_network()
                global connected_devices
                connected_devices = devices
                display_devices(devices)
                input("\n  Press Enter to continue...")
                
            elif choice == "2":
                if connected_devices:
                    print(f"\n📊 Found {len(connected_devices)} devices. Starting traffic monitor...")
                    print("  (This will show live network activity)")
                    input("  Press Enter to start monitoring...")
                    return True  # Start monitoring
                else:
                    print("\n⚠️  Please scan for devices first!")
                    input("  Press Enter to continue...")
                    
            elif choice == "3":
                print("  👋 Goodbye!")
                sys.exit(0)
                
            else:
                print("  ❌ Invalid choice. Please try again.")
                input("  Press Enter to continue...")
                
        except KeyboardInterrupt:
            print("\n  👋 Goodbye!")
            sys.exit(0)
        except Exception as e:
            print(f"  ❌ Error: {e}")
            input("  Press Enter to continue...")

def packet_callback(packet):
    timestamp = datetime.now().strftime("%H:%M:%S")
    
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        # Count all IP traffic
        interface_activity["current"] += 1
        
        # Show interesting packets
        info = ""
        
        # DNS queries
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            query = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
            info = f"🌐 DNS: {query}"
            
        # HTTP traffic  
        elif packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            
            if sport == 80 or dport == 80:
                info = f"🔗 HTTP: {ip_src}:{sport} → {ip_dst}:{dport}"
            elif sport == 443 or dport == 443:
                info = f"🔒 HTTPS: {ip_src}:{sport} → {ip_dst}:{dport}"
            elif sport == 53 or dport == 53:
                info = f"🌐 DNS: {ip_src}:{sport} → {ip_dst}:{dport}"
            else:
                info = f"📡 TCP: {ip_src}:{sport} → {ip_dst}:{dport}"
        
        # UDP traffic
        elif packet.haslayer(UDP):
            sport = packet[UDP].sport  
            dport = packet[UDP].dport
            if sport == 53 or dport == 53:
                info = f"🌐 DNS: {ip_src}:{sport} → {ip_dst}:{dport}"
            else:
                info = f"📡 UDP: {ip_src}:{sport} → {ip_dst}:{dport}"
        
        if info:
            print(f"[{timestamp}] {info}")
            
        # Progress indicator
        if interface_activity["current"] % 10 == 0:
            print(f"   📊 Captured {interface_activity['current']} packets...")

print("=" * 60)
print("  🔍  Network Traffic Monitor (All Protocols)")  
print("=" * 60)

# Show devices menu first
if show_devices_menu():
    
    print("Available interfaces:")
    for i, iface in enumerate(get_if_list(), 1):
        print(f"  {i}. {iface}")

    print("\nWhich interface? (or press Enter for interface #1): ", end="")
    try:
        choice = input().strip()
        if choice:
            interface_num = int(choice)
            interface = get_if_list()[interface_num - 1]
        else:
            interface = get_if_list()[0]
            interface_num = 1
    except (ValueError, IndexError):
        interface = get_if_list()[0] 
        interface_num = 1

    print(f"\n🎯 Monitoring interface #{interface_num}")
    print(f"   {interface}")
    
    if connected_devices:
        print(f"\n📱 Monitoring {len(connected_devices)} known devices:")
        for ip, info in list(connected_devices.items())[:5]:  # Show first 5
            name = info['name'] if info['name'] != 'Resolving...' else 'Unknown'
            print(f"   • {ip} - {name}")
        if len(connected_devices) > 5:
            print(f"   ... and {len(connected_devices) - 5} more devices")
    
    print("\nNow open a web page or do some browsing to generate traffic...")
    print("Press Ctrl+C to stop.\n")
    print("-" * 60)

    try:
        sniff(
            iface=interface,
            prn=packet_callback,
            store=0
        )
    except KeyboardInterrupt:
        print(f"\n📊 Total packets captured: {interface_activity['current']}")
        if connected_devices:
            print(f"📱 Devices on network: {len(connected_devices)}")
        print("✅ Monitoring stopped.")
    except OSError as e:
        print(f"❌ Error: {e}")
        print("Try a different interface number or run as Administrator.")