from scapy.all import sniff, IP, ICMP

def handle_packet(packet):
    if packet.haslayer(ICMP) and packet[ICMP].type == 8 and packet[IP].ttl == 1:
        packet.show()

def capture_icmp():
    sniff(filter="icmp", prn=handle_packet)

if __name__ == "__main__":
    capture_icmp()
