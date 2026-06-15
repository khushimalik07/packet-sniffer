from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import Counter
import csv
from datetime import datetime

protocol_count = Counter()

with open("packet_log.csv", "w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(["Time", "Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port"])

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        protocol = "Other"
        src_port = ""
        dst_port = ""

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif ICMP in packet:
            protocol = "ICMP"

        protocol_count[protocol] += 1

        print(f"{time} | {src_ip}:{src_port} -> {dst_ip}:{dst_port} | {protocol}")

        with open("packet_log.csv", "a", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([time, src_ip, dst_ip, protocol, src_port, dst_port])

print("Packet Sniffer Started...")
print("Capturing 50 packets...\n")

sniff(prn=packet_callback, count=50)

print("\nPacket Summary:")
for protocol, count in protocol_count.items():
    print(f"{protocol}: {count}")