from scapy.all import sniff
from scapy.layers.inet import IP, ICMP

def packet_callback(packet):
    if packet.haslayer(ICMP) and packet[IP].ttl == 1 and packet[ICMP].type == 8:
        packet.show()

if __name__ == "__main__":
    sniff(filter="icmp", prn=packet_callback) #in this line the code waits for the incoming packet
