from scapy.all import sniff, get_if_list
import sys

def test_packet(packet):
    print(f"✅ Got packet: {packet.summary()}")

print("🔍 Testing packet capture...")
print("Available interfaces:")
for i, iface in enumerate(get_if_list(), 1):
    print(f"  {i}. {iface}")

print(f"\nTrying interface #1: {get_if_list()[0]}")
print("This will capture ANY packet for 30 seconds...")
print("If you see nothing, there's a permission/setup issue.\n")

try:
    # Test with no filter - capture everything for 30 seconds
    sniff(
        iface=get_if_list()[0], 
        prn=test_packet, 
        timeout=30,
        count=10  # Stop after 10 packets
    )
    print("✅ Packet capture working!")
except Exception as e:
    print(f"❌ Error: {e}")
    print("\nPossible fixes:")
    print("1. Make sure you're running PowerShell as ADMINISTRATOR")
    print("2. Install Npcap from: https://npcap.com")
    print("3. Try interface #2 or #3 instead")