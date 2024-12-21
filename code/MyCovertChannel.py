from CovertChannelBase import CovertChannelBase
from scapy.all import IP, ICMP, Raw, sniff
import time

class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def __init__(self):
        """
        - You can edit __init__.
        """
        pass
    def send(self, log_file_name, size_for_zero, size_for_one):
        """
            Firstly, a random binary message is generated with the superclass' function. Then for each bit in the binary message, 
            a packet with a respective size is sent to the receiver. for example if size for bit=0 is 32 and size for bit=1 is 64,
            for bit = 0, a packet with contents "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" will be sent.
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name, min_length=16, max_length=16)
        # testing
        #known_message = "test."
        #binary_message = self.convert_string_message_to_binary(known_message)
        #print(binary_message)
        # testing
        #timemy = time.time()
        for bit in binary_message: 
            if bit == "0":
                payload_size = size_for_zero 
            elif bit == "1": 
                payload_size = size_for_one 
            packet = IP(dst='172.18.0.3') / ICMP() / Raw(load='A' * payload_size)
            super().send(packet)
        #timer = time.time() - timemy
        #print(timer / 128)
        

    def receive(self, size_for_zero, size_for_one, timeout, log_file_name):
        """ 
            For each packet received, I check the packet size and add the respective bit for that packet size to the binary message. 
            If the binary message length is above 8, this means we have enough bits to construct a character (since each character is 1 byte).
            Then we construct our bytes in the while loop one by one, and trim the binary message 8 bits. When we construct the character ".", 
            we set the stop_sniffing flag to true in order to finish receiving. Also, destination ip from the packet headers is checked here. That is
            because each packet comes with its duplicate if we do not check the destination ip.
        """
        binary_message = ''
        message = ''
        stop_sniffing = False
        
        def packet_handler(packet):
            nonlocal binary_message, message, stop_sniffing
            # Check if the packet has ICMP and Raw layers
            if packet.haslayer(ICMP) and packet.haslayer(Raw):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                payload_size = len(packet[Raw].load)
                #print(f"Packet received from {src_ip} to {dst_ip}, payload size: {payload_size}")
                if dst_ip == "172.18.0.3":
                    if payload_size == size_for_zero:
                        binary_message += '0'
                    elif payload_size == size_for_one:
                        binary_message += '1'
                    
                    while len(binary_message) >= 8:
                        byte = binary_message[:8]
                        binary_message = binary_message[8:]  
                        character = self.convert_eight_bits_to_character(byte)
                        message += character
                        if character == '.':
                            stop_sniffing = True
                            break
        
        def stop_filter(packet):
            return stop_sniffing

        sniff(filter='icmp', prn=packet_handler, timeout=timeout, stop_filter=stop_filter)
        
        self.log_message(message, log_file_name)