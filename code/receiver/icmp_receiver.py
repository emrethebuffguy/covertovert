from scapy.all import sniff, IP, ICMP

def handle_packet(packet):
    # Check if the packet is an ICMP request with TTL=1
    if packet.haslayer(ICMP) and packet[ICMP].type == 8 and packet[IP].ttl == 1:
        print("Received ICMP request packet with TTL=1:")
        packet.show()

def capture_icmp():
    # Capture packets with ICMP layer
    print("Listening for ICMP packets...")
    sniff(filter="icmp", prn=handle_packet)

if __name__ == "__main__":
    capture_icmp()
