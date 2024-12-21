# COVERTOVERT
Open source implementation of "network" covert channels.
This project uses a covert storage channel by varying the sizes of ICMP packets to represent binary data. 
This project demonstrates how a covert storage channel can be implemented by exploiting ICMP packet size variations. It highlights the potential for data to be transmitted covertly over networks by manipulating protocol parameters in unconventional ways.
This covert channel transmits 0.0153 bits per second.
Packet Size Variation: By altering the size of the ICMP packet payload (the data portion of the packet), we encode binary bits ('0' and '1').

## Encoding Scheme: 
- Binary '0': Represented by an ICMP packet with a specific payload size (e.g., 4 bytes).
- Binary '1': Represented by an ICMP packet with a different payload size (e.g., 8 bytes).
- Message Termination: The message ends with a specific character ('.') to signal the receiver to stop listening.

## Transmission Process:

1. Message Preparation: The sender creates a message to transmit covertly.
2. Binary Conversion: The message is converted into a binary string (a sequence of '0's and '1's).
3. Packet Encoding: Each bit in the binary string is mapped to a specific payload size based on the encoding scheme.
4. Packet Transmission: The sender sends ICMP packets with the corresponding payload sizes to the receiver.
5. Packet Reception: The receiver listens for ICMP packets and records the payload sizes.
6. Binary Decoding: The receiver maps the payload sizes back to binary bits.
7. Message Reconstruction: The receiver reconstructs the original message from the binary data.

## Usage Guide: 
1. Set the paramters in config.json (size_for_zero and size_for_one must be the same for receiver and sender).
2. Run the receiver with make receive.
3. Run the sender with make send.
4. The logs for sender and receiver will be logged to their respective files.
5. With make compare, sender and receiver logs can be compared.