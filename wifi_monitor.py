from scapy.all import (
    sniff, srp, ARP, Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw,
    get_if_list, get_if_addr, conf
)
from collections import defaultdict
from datetime import datetime
from mac_vendor_lookup import MacLookup
import socket
import subprocess
import sys
import threading
import time
import os

# ============================================================
#  WiFi Network Monitor v2 — Device Names + Browsing Activity
# ============================================================

devices = {}
LOCAL_IP = None
GATEWAY_IP = None
INTERFACE = None
lock = threading.Lock()
mac_lookup = None


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "unknown"


def get_gateway():
    try:
        gw = conf.route.route("0.0.0.0")[2]
        if gw and gw != "0.0.0.0":
            return gw
    except Exception:
        pass
    parts = LOCAL_IP.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.1"


def init_mac_lookup():
    global mac_lookup
    try:
        mac_lookup = MacLookup()
        mac_lookup.update_vendors()
        print("  ✅ MAC vendor database loaded.")
    except Exception:
        try:
            mac_lookup = MacLookup()
            print("  ✅ MAC vendor database loaded (cached).")
        except Exception:
            mac_lookup = None
            print("  ⚠️  MAC vendor database unavailable.")


def lookup_vendor(mac):
    if mac_lookup and mac != "unknown":
        try:
            return mac_lookup.lookup(mac)
        except Exception:
            pass
    return "Unknown"


def get_netbios_name(ip):
    """Get Windows device name via nbtstat."""
    try:
        result = subprocess.run(
            ["nbtstat", "-a", ip],
            capture_output=True, text=True, timeout=3
        )
        for line in result.stdout.split("\n"):
            line = line.strip()
            if "<00>" in line and "UNIQUE" in line:
                name = line.split("<00>")[0].strip()
                if name and len(name) > 1:
                    return name
    except Exception:
        pass
    return ""


def new_device(ip, mac="unknown"):
    vendor = lookup_vendor(mac)
    return {
        "mac": mac,
        "vendor": vendor,
        "name": "",
        "sites": set(),
        "last_seen": datetime.now(),
        "packets": 0,
    }


def get_display_name(ip):
    with lock:
        d = devices.get(ip, {})
    if ip == LOCAL_IP:
        return "THIS PC"
    if ip == GATEWAY_IP:
        return "ROUTER"
    name = d.get("name") or d.get("vendor", "Unknown")
    if name == "Unknown":
        return ip
    return name


# ==============================================================
#  NETWORK SCAN
# ==============================================================
def scan_network(resolve_names=True):
    global devices
    subnet = ".".join(LOCAL_IP.split(".")[:3]) + ".0/24"
    print(f"\n  📡 Scanning network: {subnet} ...")

    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
            iface=INTERFACE, timeout=5, verbose=0,
        )
        with lock:
            for sent, received in ans:
                ip = received.psrc
                mac = received.hwsrc
                if ip not in devices:
                    devices[ip] = new_device(ip, mac)
                else:
                    devices[ip]["mac"] = mac
                    if devices[ip]["vendor"] == "Unknown":
                        devices[ip]["vendor"] = lookup_vendor(mac)
                devices[ip]["last_seen"] = datetime.now()

        print(f"  ✅ Found {len(devices)} devices on the network.")

        if resolve_names:
            print(f"  🔍 Resolving device names (please wait ~30s)...\n")

            def resolve(ip):
                with lock:
                    mac = devices[ip]["mac"]
                name = get_netbios_name(ip)
                if not name:
                    try:
                        name = socket.gethostbyaddr(ip)[0]
                    except Exception:
                        name = ""
                vendor = lookup_vendor(mac)
                with lock:
                    if name:
                        devices[ip]["name"] = name
                    if vendor != "Unknown":
                        devices[ip]["vendor"] = vendor

            threads = []
            for ip in list(devices.keys()):
                t = threading.Thread(target=resolve, args=(ip,))
                t.start()
                threads.append(t)
            for t in threads:
                t.join(timeout=5)

            print(f"  ✅ Device names resolved.\n")
    except Exception as e:
        print(f"  ⚠️  ARP scan error: {e}")


def periodic_scan(interval=120):
    while True:
        time.sleep(interval)
        scan_network(resolve_names=False)


# ==============================================================
#  PACKET CALLBACK
# ==============================================================
def packet_callback(packet):
    if not packet.haslayer(IP):
        return

    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    timestamp = datetime.now().strftime("%H:%M:%S")
    subnet = ".".join(LOCAL_IP.split(".")[:3]) + "."

    device_ip = None
    if ip_src.startswith(subnet) and ip_src != GATEWAY_IP:
        device_ip = ip_src
    elif ip_dst.startswith(subnet) and ip_dst != GATEWAY_IP:
        device_ip = ip_dst

    if device_ip:
        with lock:
            if device_ip not in devices:
                devices[device_ip] = new_device(device_ip)
            devices[device_ip]["last_seen"] = datetime.now()
            devices[device_ip]["packets"] += 1

    # ------ DNS Queries ------
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        query = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
        if any(skip in query.lower() for skip in [
            ".local", ".arpa", "_dns", "localhost", "wpad",
            "_tcp", "_udp", "._", ".lan", "_ntp", "gateway",
        ]):
            return

        source_ip = ip_src if ip_src.startswith(subnet) else None
        if source_ip:
            with lock:
                if source_ip not in devices:
                    devices[source_ip] = new_device(source_ip)
                devices[source_ip]["sites"].add(query)
            dname = get_display_name(source_ip)
            print(f"  [{timestamp}]  🌐 DNS   | {source_ip} ({dname})")
            print(f"                        → {query}")
            print("-" * 70)

    # ------ HTTP (port 80) ------
    elif packet.haslayer(TCP) and packet.haslayer(Raw):
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        if dport == 80 or sport == 80:
            try:
                payload = packet[Raw].load.decode("utf-8", errors="ignore")
            except Exception:
                return
            if payload.startswith(("GET", "POST", "PUT", "DELETE", "HEAD")):
                lines = payload.split("\r\n")
                request_line = lines[0].strip()
                host = ""
                for line in lines:
                    if line.lower().startswith("host:"):
                        host = line.split(":", 1)[1].strip()
                        break
                source_ip = ip_src if ip_src.startswith(subnet) else None
                if source_ip:
                    with lock:
                        if source_ip not in devices:
                            devices[source_ip] = new_device(source_ip)
                        if host:
                            devices[source_ip]["sites"].add(host)
                    dname = get_display_name(source_ip)
                    print(f"  [{timestamp}]  🔗 HTTP  | {source_ip} ({dname})")
                    print(f"                        → {request_line}")
                    if host:
                        print(f"                        🌐 {host}")
                    print("-" * 70)

    # ------ HTTPS SYN (port 443) ------
    elif packet.haslayer(TCP):
        dport = packet[TCP].dport
        if dport == 443 and packet[TCP].flags == "S":
            source_ip = ip_src if ip_src.startswith(subnet) else None
            if source_ip:
                try:
                    dest_name = socket.gethostbyaddr(ip_dst)[0]
                except Exception:
                    dest_name = ip_dst
                with lock:
                    if source_ip not in devices:
                        devices[source_ip] = new_device(source_ip)
                    if dest_name != ip_dst:
                        devices[source_ip]["sites"].add(dest_name)
                dname = get_display_name(source_ip)
                print(f"  [{timestamp}]  🔒 HTTPS | {source_ip} ({dname}) → {dest_name}")

    # ------ mDNS (port 5353) — discover device names ------
    if packet.haslayer(UDP):
        if packet[UDP].dport == 5353 or packet[UDP].sport == 5353:
            source_ip = ip_src if ip_src.startswith(subnet) else None
            if source_ip and packet.haslayer(DNSRR):
                try:
                    rr = packet[DNSRR].rrname.decode("utf-8", errors="ignore").rstrip(".")
                    clean = rr.replace(".local", "").split(".")[0]
                    if clean and len(clean) > 1 and "._" not in rr:
                        with lock:
                            if source_ip not in devices:
                                devices[source_ip] = new_device(source_ip)
                            if not devices[source_ip]["name"]:
                                devices[source_ip]["name"] = clean
                        print(f"  [{datetime.now().strftime('%H:%M:%S')}]  📱 mDNS  | Discovered: {source_ip} = \"{clean}\"")
                        print("-" * 70)
                except Exception:
                    pass

        # NetBIOS (port 137) — Windows device names
        if packet[UDP].dport == 137 or packet[UDP].sport == 137:
            source_ip = ip_src if ip_src.startswith(subnet) else None
            if source_ip:
                try:
                    raw = bytes(packet[UDP].payload)
                    if len(raw) > 56:
                        encoded = raw[13:45]
                        name = ""
                        for i in range(0, 30, 2):
                            if i + 1 < len(encoded):
                                c = ((encoded[i] - 0x41) << 4) | (encoded[i + 1] - 0x41)
                                if 32 <= c < 127:
                                    name += chr(c)
                        name = name.strip()
                        if name and len(name) > 1 and "CKAAAAAA" not in name:
                            with lock:
                                if source_ip not in devices:
                                    devices[source_ip] = new_device(source_ip)
                                if not devices[source_ip]["name"]:
                                    devices[source_ip]["name"] = name
                            print(f"  [{datetime.now().strftime('%H:%M:%S')}]  💻 NBNS  | Discovered: {source_ip} = \"{name}\"")
                            print("-" * 70)
                except Exception:
                    pass


# ==============================================================
#  SUMMARY TABLE
# ==============================================================
def print_device_table():
    print("\n" + "=" * 75)
    print("  📊  ALL CONNECTED DEVICES & BROWSING ACTIVITY")
    print("=" * 75)

    with lock:
        sorted_devices = sorted(devices.items(), key=lambda x: x[0])

    for ip, data in sorted_devices:
        if ip == LOCAL_IP:
            icon, label = "⭐", "THIS PC"
        elif ip == GATEWAY_IP:
            icon, label = "🌐", "ROUTER"
        else:
            icon = "📱"
            label = data.get("name") or data.get("vendor", "Unknown")

        mac = data["mac"]
        vendor = data["vendor"]
        name = data.get("name", "")
        pkts = data["packets"]
        last = data["last_seen"].strftime("%H:%M:%S")

        print(f"\n  {icon} {label}")
        print(f"     IP       : {ip}")
        print(f"     MAC      : {mac}")
        print(f"     Vendor   : {vendor}")
        if name and name != label:
            print(f"     Name     : {name}")
        print(f"     Packets  : {pkts}")
        print(f"     Last Seen: {last}")

        if data["sites"]:
            clean_sites = set()
            for site in data["sites"]:
                parts = site.split(".")
                if len(parts) >= 2:
                    main = ".".join(parts[-2:])
                else:
                    main = site
                clean_sites.add(main)
            print(f"     🌐 Sites ({len(clean_sites)} domains):")
            for site in sorted(clean_sites):
                print(f"        • {site}")
        else:
            print(f"     🌐 No browsing captured yet")

    print("\n" + "=" * 75)
    print(f"  Total devices: {len(devices)}")
    print("=" * 75)


# ==============================================================
#  MAIN
# ==============================================================
if __name__ == "__main__":
    LOCAL_IP = get_local_ip()
    GATEWAY_IP = get_gateway()

    clear()
    print("=" * 70)
    print("  📡  WiFi Network Monitor v2")
    print("  Captures device names + browsing of all WiFi devices")
    print("=" * 70)
    print(f"  Your IP  : {LOCAL_IP}")
    print(f"  Gateway  : {GATEWAY_IP}")
    print()

    init_mac_lookup()

    ifaces = get_if_list()
    print("\n  Network Interfaces:")
    print("  " + "-" * 60)
    for i, iface in enumerate(ifaces, 1):
        try:
            ip = get_if_addr(iface)
        except Exception:
            ip = ""
        marker = "  ← YOUR WIFI" if ip == LOCAL_IP else ""
        ip_str = f"  ({ip})" if ip and ip != "0.0.0.0" else ""
        print(f"    {i}. {iface}{ip_str}{marker}")
    print("  " + "-" * 60)

    INTERFACE = None
    for iface in ifaces:
        try:
            if get_if_addr(iface) == LOCAL_IP:
                INTERFACE = iface
                break
        except Exception:
            pass

    if INTERFACE:
        print(f"\n  ✅ Auto-detected your WiFi interface!")
    else:
        print("\n  Enter interface number: ", end="")
        try:
            choice = int(input().strip())
            INTERFACE = ifaces[choice - 1]
        except (ValueError, IndexError):
            INTERFACE = ifaces[0]

    print(f"  🎯 Using: {INTERFACE}\n")

    scan_network(resolve_names=True)
    print_device_table()

    threading.Thread(target=periodic_scan, args=(120,), daemon=True).start()

    print("\n" + "=" * 70)
    print("  🔴 LIVE MONITORING")
    print("  Watching: DNS | HTTP | HTTPS | mDNS | NetBIOS")
    print("  Press Ctrl+C to stop and see full summary.")
    print("=" * 70 + "\n")

    try:
        sniff(
            iface=INTERFACE,
            prn=packet_callback,
            filter="port 53 or port 80 or port 443 or port 5353 or port 137",
            store=0,
        )
    except KeyboardInterrupt:
        print_device_table()
        print("\n✅ Monitoring stopped.")
        sys.exit(0)
    except OSError as e:
        print(f"\n❌ Error: {e}")
        print("   Run PowerShell as Administrator!")
        sys.exit(1)
