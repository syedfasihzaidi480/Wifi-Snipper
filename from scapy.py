from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw, get_if_list, conf
from collections import defaultdict
from datetime import datetime
import sys
import socket

# ============================================================
#  WiFi Network Sniffer — See browsing activity of devices
# ============================================================

# Track unique devices and their browsing activity
devices_seen = defaultdict(lambda: {"sites": set(), "count": 0})

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

def list_interfaces():
    """List all available network interfaces."""
    print("\n Available Network Interfaces:")
    print("-" * 50)
    for i, iface in enumerate(get_if_list(), 1):
        print(f"  {i}. {iface}")
    print("-" * 50)

def packet_callback(packet):
    if not packet.haslayer(IP):
        return

    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    timestamp = datetime.now().strftime("%H:%M:%S")

    # ----------------------------------------------------------
    # 1) DNS Queries — Most reliable way to see browsed sites
    #    (works even for HTTPS traffic)
    # ----------------------------------------------------------
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        query_name = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
        # Skip internal / noise queries
        if any(skip in query_name for skip in [
            "local", "arpa", "_dns", "localhost",
            "windowsupdate", "microsoft.com", "msftconnecttest"
        ]):
            return

        devices_seen[ip_src]["sites"].add(query_name)
        devices_seen[ip_src]["count"] += 1

        direction = "OUT →" if ip_src == LOCAL_IP else "IN  ←"
        print(f"  [{timestamp}] [DNS] [{direction}] Device {ip_src}")
        print(f"           🌐 Browsing: {query_name}")
        print("-" * 60)

    # ----------------------------------------------------------
    # 2) HTTP Traffic (port 80) — Extract URLs from GET/POST
    # ----------------------------------------------------------
    elif packet.haslayer(TCP) and packet.haslayer(Raw):
        tcp_sport = packet[TCP].sport
        tcp_dport = packet[TCP].dport

        if tcp_dport == 80 or tcp_sport == 80:
            try:
                payload = packet[Raw].load.decode("utf-8", errors="ignore")
            except Exception:
                return

            if payload.startswith(("GET", "POST", "PUT", "DELETE", "HEAD")):
                lines = payload.split("\r\n")
                request_line = lines[0].strip() if lines else ""
                host = ""
                for line in lines:
                    if line.lower().startswith("host:"):
                        host = line.split(":", 1)[1].strip()
                        break

                url = f"http://{host}{request_line.split(' ')[1]}" if host else request_line
                devices_seen[ip_src]["sites"].add(host or url)
                devices_seen[ip_src]["count"] += 1

                direction = "OUT →" if ip_src == LOCAL_IP else "IN  ←"
                print(f"  [{timestamp}] [HTTP] [{direction}] Device {ip_src}")
                print(f"           🔗 {request_line}")
                print(f"           🌐 Host: {host}")
                print("-" * 60)

    # ----------------------------------------------------------
    # 3) HTTPS Traffic (port 443) — Log connection (no content)
    # ----------------------------------------------------------
    elif packet.haslayer(TCP):
        tcp_dport = packet[TCP].dport
        if tcp_dport == 443 and packet[TCP].flags == "S":  # SYN = new connection
            devices_seen[ip_src]["count"] += 1
            direction = "OUT →" if ip_src == LOCAL_IP else "IN  ←"
            print(f"  [{timestamp}] [HTTPS] [{direction}] Device {ip_src} → {ip_dst}:443 (encrypted)")


def print_summary():
    """Print summary of all devices and their browsing activity."""
    print("\n" + "=" * 60)
    print(" 📊  SESSION SUMMARY — Devices & Sites Visited")
    print("=" * 60)
    for device_ip, data in sorted(devices_seen.items()):
        label = "(this machine)" if device_ip == LOCAL_IP else ""
        print(f"\n  📱 Device: {device_ip} {label}")
        print(f"     Packets: {data['count']}")
        if data["sites"]:
            print("     Sites visited:")
            for site in sorted(data["sites"]):
                print(f"       • {site}")
    print("\n" + "=" * 60)


# ============================================================
#  MAIN
# ============================================================
LOCAL_IP = get_local_ip()
print("=" * 60)
print("  📡  WiFi Network Browser Sniffer")
print("=" * 60)
print(f"  Local IP : {LOCAL_IP}")

# List interfaces so user can pick the right one
list_interfaces()

# Let user choose interface
print("\n  Which interface do you want to monitor?")
print("  💡 Tip: Usually interface #1 or #2 is your main network adapter")
try:
    choice = int(input("  Enter number (1-{}): ".format(len(get_if_list()))))
    if 1 <= choice <= len(get_if_list()):
        interface = get_if_list()[choice - 1]
    else:
        print("❌ Invalid choice. Using interface #1")
        interface = get_if_list()[0]
except (ValueError, KeyboardInterrupt):
    print("\n❌ Invalid input. Using interface #1")
    interface = get_if_list()[0]

print(f"\n  🎯 Sniffing on: {interface}")
print("  Press Ctrl+C to stop.\n")
print("-" * 60)

try:
    # Filter: DNS (port 53) + HTTP (port 80) + HTTPS (port 443)
    sniff(
        iface=interface,
        prn=packet_callback,
        filter="port 53 or port 80 or port 443",
        store=0,
    )
except KeyboardInterrupt:
    print_summary()
    print("\n✅ Stopped sniffing.")
    sys.exit(0)
except OSError as e:
    print(f"\n❌ Error: {e}")
    print("   Make sure you're running as Administrator and the interface name is correct.")
    list_interfaces()
    sys.exit(1)