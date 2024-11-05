from scapy.all import IP, ICMP, send

def send_icmp_packet():
    target_ip = "172.18.0.3"
    
    ip_packet = IP(dst=target_ip, ttl=1)
    
    icmp_packet = ICMP(type="echo-request")
    
    packet = ip_packet / icmp_packet
    
    send(packet)

if __name__ == "__main__":
    send_icmp_packet()
