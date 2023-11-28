from scapy.all import sniff, Ether, IP

def packet_callback(packet):
    if packet.haslayer(Ether) and packet.haslayer(IP):
        if (packet[Ether].src == '00:11:22:33:44:55' and 
            packet[Ether].dst == '55:44:33:22:11:00' and 
            packet[IP].dst == '192.168.0.2'):
            
            print("Packet captured")
            print(f"Source IP: {packet[IP].src}")
            print(f"Destination IP: {packet[IP].dst}")
            print(f"Protocol: {packet[IP].proto}")

print("SNIFFING PACKETS...")
sniff(prn = packet_callback, timeout = 10)