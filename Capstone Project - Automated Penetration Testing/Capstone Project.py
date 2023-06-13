#Capstobne Project
#Members: Aw Jin Le Ray, Kim Junghan, Lucas Sim
import sys
import nmap
import shodan
import sqlite3
from sqlite3 import Error
import pyfiglet
import os
import scrapy
from scrapy.spiders import CrawlSpider, Rule
from scrapy.linkextractors import LinkExtractor
from googlesearch import search #pip install beautifulsoup4 and google

#Shodan API KEY
Shodan_APIKEY = 'EBeU0lGqtIO6yCxVFCWC4nUVbvovtjo5'
api = shodan.Shodan(Shodan_APIKEY)
conn = sqlite3.connect("APTdatabase.db")
cur = conn.cursor()
loop = True
def project_menu():
    ascii_hi = pyfiglet.figlet_format("Welcome to Automated Pentesting!")
    print(ascii_hi)
    print("\nPlease Select an Option Below.")
    print("1. Port scanning")
    print("Spider")
    print("Option 3")
    print("4. OS Scan")
    print("5. Spidering")
    print("6. Exit\n")
    menu_input = int()
    while menu_input == int():
        menu_input = int(input("Select option: "))
        if menu_input == 1:
            ascii_nmap = pyfiglet.figlet_format("Welcome to Port Scanning!")
            print(ascii_nmap)
            html()
            option_1()
        elif menu_input == 2:
            option_2()
        elif menu_input == 3:
            option_3()
        elif menu_input == 4:
            option_4()
        elif menu_input == 5:
            ascii_spider = pyfiglet.figlet_format("Welcome to Spidering!")
            print(ascii_spider)
            cmd = os.system('cmd /k "scrapy runspider spider.py"')
            print(cmd)
        elif menu_input == 6:
            droptables()
            ascii_bye = pyfiglet.figlet_format("Goodbye!")
            print(ascii_bye)
            sys.exit()
        else:
            print("Invalid Input!\nPlease Try Again!")
            continue

def option_1():
    target = input("Enter an IP Address to scan: ")
    port_range = input("Enter the range of ports to scan (eg. 1-1024): ")
    scanner = nmap.PortScanner()
    scanner.scan(target, port_range)
    conn.execute('''CREATE TABLE IF NOT EXISTS PortScanning
        (port_number TEXT, port_status TEXT)''')
    conn.commit()
    for host in scanner.all_hosts():
         print('Host : %s (%s)' % (host, scanner[host].hostname()))
         print('State : %s' % scanner[host].state())
         for proto in scanner[host].all_protocols():
             print('----------')
             print('Protocol : %s' % proto)
     
             lport = scanner[host][proto].keys()
             for port in lport:
                 plist = (str(port), str(scanner[host][proto][port]['state']))
                 cur.execute('''
                    INSERT INTO PortScanning (port_number, port_status) VALUES (?, ?)
                    ''', plist)
                 conn.commit()
                 print ('port : %s\tstate : %s' % (port, scanner[host][proto][port]['state']))
                 plist = ()
                
def option_2():
    print("This is option 2 function")
    target = input("Enter an IP Address to scan: ")
    #target = 'www.cloudfare.com'
    #dnsResolve = 'https://api.shodan.io/dns/resolve?hostnames=' + target + '&key=' + Shodan_APIKEY
    try:
        ## First we need to resolve our targets domain to an IP
        #resolved = requests.get(dnsResolve)
        #hostIP = resolved.json()[target]
        print(target)

        # Then we need to do a Shodan search on that IP
        host = api.host(target)
        print("IP: %s" % host['ip_str'])
        print("Organization: %s" % host.get('org', 'n/a'))
        print("Operating System: %s" % host.get('os', 'n/a'))

        # Print all banners
        for item in host['data']:
            print("Port: %s" % item['port'])
            print("Banner: %s" % item['data'])

    except:
        'An error occured'

    #ipinfo = api.host('104.16.133.229')
    #print(ipinfo)



def option_3():
    print("This is option 3 function")
    target = input("Enter an IP Address to scan: ")
    nm = nmap.PortScanner()

    nm.scan(hosts=target, arguments='-n -sP')
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]

    for host, status in hosts_list:
        print(host + ' ' + status)

def option_4():
    target = input("Enter an IP Address to scan: ")
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments='-O')
    if scanner[target]['osmatch']:
        print('Operating System: ' + scanner[target]['osmatch'][0]['name'])
    else:
        print('Failed to determine operating system')

def droptables():
    conn.execute('''DELETE FROM PortScanning''')
    conn.commit()
    cur.close()
    conn.close()
 
#SNMP OS Enumuration
def snmpOS():
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
                else:
                    print("Port 161 (SNMP) not opened, can't perform SNMP Enumuration")
#SNMP Processes Enumuration
def snmpProcesses():
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
                else:
                    print("Port 161 (SNMP) not opened, can't perform SNMP Enumuration")
#SNMP Software Enumuration
def snmpSoftware():
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
                else:
                    print("Port 161 (SNMP) not opened, can't perform SNMP Enumuration")

#SNMP Interface Enumuration
def snmpInterface():
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
                else:
                    print("Port 161 (SNMP) not opened, can't perform SNMP Enumuration")


#SMTP Users Enumuration
def smtpUsers():
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
            else:
                print("Port 25 (SMTP) not opened, can't perform SMTP Enumuration")

#NFS Share Enumuration
def nfsShare():
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
            else:
                print("Port 2049 (NFS) not opened, can't perform NFS Enumuration")

def googleShare():
    toSearch = input("What do you want to search? ")
    print("\nResults:")
    for searchItem in search(toSearch, num=10, stop=10):
        print(searchItem)

while loop == True:
    project_menu()
