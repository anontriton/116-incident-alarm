#!/usr/bin/python3

from scapy.all import *
import argparse

incident_num = 0

def alert(incident_type, src_ip, protocol, payload=""):
    global incident_num
    incident_num += 1
    print(f"ALERT #{incident_num}: {incident_type} is detected from {src_ip} ({protocol}) ({payload})!")

def scan_null(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == 0x00: # no flags
        alert("NULL scan", packet[IP].src, "TCP", "")

def scan_fin(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == 0x01: # just fin flag
        alert("FIN scan", packet[IP].src, "TCP", "")
        
def scan_xmas(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == 0x29: # fin, psh, urg flags
        alert("Xmas scan", packet[IP].src, "TCP", "Merry Christmas!")

def scan_plaintxt(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load
    
    # HTTP
    if packet[TCP].dport == 80:
        if "Authorization: Basic" in payload:
            alert("Usernames and passwords sent in-the-clear (HTTP)", packet[IP].src, "HTTP", payload.decode())

    # FTP
    if packet[TCP].dport == 21:
        if "USER" in payload or "PASS" in payload:
            alert("Usernames and passwords sent in-the-clear (FTP)", packet[IP].src, "FTP", payload.decode())

    # IMAP
    if packet[TCP].dport == 143:
        if "LOGIN" in payload:
            alert("Usernames and passwords sent in-the-clear (IMAP)", packet[IP].src, "IMAP", payload.decode())


def scan_nikto(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 80 and packet.haslayer(Raw):
        if "User-Agent: Mozilla/5.00 (Nikto" in packet.load:
            alert("Nikto scan", packet[IP].src, "HTTP", packet.load.decode())


def packetcallback(packet):
    try:
        
        # NULL scan
        scan_null(packet[0])

        # FIN scan
        scan_fin(packet[0])

        # Xmas scan
        scan_xmas(packet[0])

        # usernames and passwords sent in-the-clear
        scan_plaintxt(packet[0])

        # Nikto scan
        scan_nikto(packet[0])

        # scanning for SMB protocol

        # scanning for RDP

        # scanning for VNC instance(s)



    except Exception as e:
        print(e)

# DO NOT MODIFY THE CODE BELOW
parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
print("Sniffing on %(interface)s... " % {"interface" : args.interface})
try:
    sniff(iface=args.interface, prn=packetcallback)
except:
    print("Sorry, can\'t read network traffic. Are you root?")