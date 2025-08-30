from scapy.all import sniff, IP, TCP, UDP, Ether, conf

def packet_handler(pkt):
    print("\n=== Packet ===")
    if Ether in pkt:
        print(f"MAC {pkt[Ether].src} -> {pkt[Ether].dst}")
    if IP in pkt:
        print(f"IP  {pkt[IP].src} -> {pkt[IP].dst}")
        if TCP in pkt:
            print(f"TCP {pkt[TCP].sport} -> {pkt[TCP].dport}")
        elif UDP in pkt:
            print(f"UDP {pkt[UDP].sport} -> {pkt[UDP].dport}")
        if pkt.haslayer("Raw"):
            payload = pkt["Raw"].load
            print(f"Payload: {payload[:50]}...")

print("Starting capture... Ctrl+C to stop.")
try:
    # Try normal (Layer-2) sniffing – requires Npcap/WinPcap
    sniff(prn=packet_handler, store=False, count=10)
except RuntimeError as e:
    print(f"Layer-2 sniff failed: {e}")
    print("Falling back to Layer-3 (no Npcap needed).")
    # Optional: choose a specific interface, e.g. "Wi-Fi"
    # from scapy.all import show_interfaces; show_interfaces()
    # conf.iface = "Wi-Fi"
    l3sock = conf.L3socket()           # IPv4 L3 socket
    sniff(opened_socket=l3sock, prn=packet_handler, store=False, count=10)
