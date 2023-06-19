#Capstobne Project
#Members: Aw Jin Le Ray, Kim Junghan, Lucas Sim
import sys
import nmap
import shodan
import sqlite3
from sqlite3 import Error
import pyfiglet
import os
import scrapy #pip install scrapy
from scrapy.spiders import CrawlSpider, Rule
from scrapy.linkextractors import LinkExtractor
from googlesearch import search #pip install beautifulsoup4 and google
import requests #pip install requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup #pip install bs4
import colorama #pip install colorama

#Shodan API KEY
Shodan_APIKEY = 'EBeU0lGqtIO6yCxVFCWC4nUVbvovtjo5'
api = shodan.Shodan(Shodan_APIKEY)
#Spidering Global Variables
total_urls_visited = 0
#Setting Up Database
conn = sqlite3.connect("APTdatabase.db")
cur = conn.cursor()
def createtables():
    conn.execute('''CREATE TABLE IF NOT EXISTS Spidering
    (Internal_URLs TEXT, External_URLs TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS PortScanning
    (IP_Address TEXT, Port_Number TEXT, Port_Status TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS SNMP_OS_Enummeration
    (IP_Address TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, Hardware TEXT, Software TEXT, System_uptime TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS SNMP_Process_Enummeration
    (IP_Address TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, Processes TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS SNMP_Software_Enummeration
    (IP_Address TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, Softwares TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS SNMP_Interface_Enummeration
    (IP_Address TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, Interfaces TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS SMTP_User_Enummeration
    (IP_Address TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, Users TEXT)''')
    conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS NFS_Share_Enummeration
    (IP_Address TEXT, Protocol TEXT, Port_Number TEXT, Port_Status TEXT, Shares TEXT)''')
    conn.commit()

def droptables():
    conn.execute('''DELETE FROM PortScanning''')
    conn.commit()
    conn.execute('''DELETE FROM Spidering''')
    conn.commit()
    conn.execute('''DELETE FROM SNMP_OS_Enummeration''')
    conn.commit()
    conn.execute('''DELETE FROM SNMP_Process_Enummeration''')
    conn.commit()
    conn.execute('''DELETE FROM SNMP_Software_Enummeration''')
    conn.commit()
    conn.execute('''DELETE FROM SNMP_Interface_Enummeration''')
    conn.commit()
    conn.execute('''DELETE FROM SMTP_User_Enummeration''')
    conn.commit()
    conn.execute('''DELETE FROM NFS_Share_Enummeration''')
    conn.commit()
    cur.close()
    conn.close()
createtables()
loop = True
def project_menu():
    ascii_hi = pyfiglet.figlet_format("Welcome to Automated Pentesting!")
    print(ascii_hi)
    print("\nPlease Select an Option Below.")
    print("1. Port scanning")
    print("2. ???")
    print("3. ???")
    print("4. OS Scan")
    print("5. Spidering")
    print("6. Enummeration shiz")
    print("7. Exit")
    menu_input = int()
    while menu_input == int():
        menu_input = int(input("\nSelect option: "))
        if menu_input == 1:
            ascii_nmap = pyfiglet.figlet_format("Welcome to Port Scanning!")
            print(ascii_nmap)
            # html()
            portscanning()
        elif menu_input == 2:
            option_2()
        elif menu_input == 3:
            option_3()
        elif menu_input == 4:
            option_4()
        elif menu_input == 5:
            ascii_spider = pyfiglet.figlet_format("Welcome to Spidering!")
            print(ascii_spider)
            spidering()
            # cmd = os.system('cmd /k "scrapy runspider spider.py"')
            # print(cmd)
        elif menu_input == 6:
            nfsShare()
        elif menu_input == 7:
            droptables()
            ascii_bye = pyfiglet.figlet_format("Goodbye!")
            print(ascii_bye)
            sys.exit()
        else:
            print("Invalid Input!\nPlease Try Again!")
            continue

def portscanning():
    target = input("Enter an IP Address to scan: ")
    port_range = input("Enter the range of ports to scan (e.g. 1-1024): ")
    scanner = nmap.PortScanner()
    scanner.scan(target, port_range)
    for host in scanner.all_hosts():
         print('Host : %s (%s)' % (host, scanner[host].hostname()))
         print('State : %s' % scanner[host].state())
         for proto in scanner[host].all_protocols():
             print('----------')
             print('Protocol : %s' % proto)
     
             lport = scanner[host][proto].keys()
             for port in lport:
                 plist = (str(target), str(port), str(scanner[host][proto][port]['state']))
                 cur.execute('''
                    INSERT INTO PortScanning (IP_Address, Port_Number, Port_Status) VALUES (?, ?, ?)
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
 
#SNMP OS Enumuration
def snmpOS():
    snmpOSList = []
    scanner = nmap.PortScanner()
    target = input("Enter IP Address: ")
    snmpOSList.append(target)
    scanner.scan(target, arguments='-sU -p 161')
    for host in scanner.all_hosts():
        print(host)
        for proto in scanner[host].all_protocols():
            snmpOSList.append(proto)
            print('----------')
            print('Protocol : %s' % proto)

            lport = scanner[host][proto].keys()
            for port in lport:
                if scanner[host][proto][port]['state'] == "open":
                    snmpOSList.append(port)
                    snmpOSList.append(scanner[host][proto][port]['state'])
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
                    snmpOSList.append(snmp[host][proto][port]['script']['snmp-sysdescr'][list[0]:list[1]-12])
                    snmpOSList.append(snmp[host][proto][port]['script']['snmp-sysdescr'][list[1]:list[2]-15])
                    snmpOSList.append(snmp[host][proto][port]['script']['snmp-sysdescr'][list[2]:])
                    cur.execute('''
                    INSERT INTO SNMP_OS_Enummeration (IP_Address, Protocol, Port_Number, Port_Status, Hardware, Software, System_uptime) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', snmpOSList)
                    conn.commit()
                else:
                    print("Port 161 (SNMP) not opened, can't perform SNMP Enumuration")

#SNMP Processes Enumuration
def snmpProcesses():
    snmpProcessesList = []
    scanner = nmap.PortScanner()
    target = input("Enter IP Address: ")
    snmpProcessesList.append(target)
    scanner.scan(target, arguments='-sU -p 161')
    for host in scanner.all_hosts():
        print(host)
        for proto in scanner[host].all_protocols():
            snmpProcessesList.append(proto)
            print('----------')
            print('Protocol : %s' % proto)
     
            lport = scanner[host][proto].keys()
            for port in lport:
                if scanner[host][proto][port]['state'] == "open":
                    snmpProcessesList.append(port)
                    snmpProcessesList.append(scanner[host][proto][port]['state'])
                    print ('port : %s\tstate : %s'
                            % (port, scanner[host][proto][port]['state']))
                    snmp = nmap.PortScanner()
                    snmp.scan(host, arguments='-sU -p 161 --script snmp-processes')
                    print(snmp[host][proto][port]['script']['snmp-processes'])
                    snmpProcessesList.append(snmp[host][proto][port]['script']['snmp-processes'])
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
                    cur.execute('''
                    INSERT INTO SNMP_Process_Enummeration (IP_Address, Protocol, Port_Number, Port_Status, Processes) VALUES (?, ?, ?, ?, ?)
                    ''', snmpProcessesList)
                    conn.commit()
                else:
                    print("Port 161 (SNMP) not opened, can't perform SNMP Enumuration")
    
#SNMP Software Enumuration
def snmpSoftware():
    snmpSoftwareList = []
    scanner = nmap.PortScanner()
    target = input("Enter IP Address: ")
    snmpSoftwareList.append(target)
    scanner.scan(target, arguments='-sU -p 161')
    for host in scanner.all_hosts():
        print(host)
        for proto in scanner[host].all_protocols():
            snmpSoftwareList.append(proto)
            print('----------')
            print('Protocol : %s' % proto)
     
            lport = scanner[host][proto].keys()
            for port in lport:
                if scanner[host][proto][port]['state'] == "open":
                    snmpSoftwareList.append(port)
                    snmpSoftwareList.append(scanner[host][proto][port]['state'])
                    print ('port : %s\tstate : %s'
                            % (port, scanner[host][proto][port]['state']))
                    snmp = nmap.PortScanner()
                    snmp.scan(host, arguments='-sU -p 161 --script snmp-win32-software')
                    print(snmp[host][proto][port]['script']['snmp-win32-software'])
                    cur.execute('''
                    INSERT INTO SNMP_Software_Enummeration (IP_Address, Protocol, Port_Number, Port_Status, Softwares) VALUES (?, ?, ?, ?, ?)
                    ''', snmpSoftwareList)
                    conn.commit()
                else:
                    print("Port 161 (SNMP) not opened, can't perform SNMP Enumuration")

#SNMP Interface Enumuration
def snmpInterface():
    snmpInterfaceList = []
    scanner = nmap.PortScanner()
    target = input("Enter IP Address: ")
    snmpInterfaceList.append(target)
    scanner.scan(target, arguments='-sU -p 161')
    for host in scanner.all_hosts():
        print(host)
        for proto in scanner[host].all_protocols():
            snmpInterfaceList.append(proto)
            print('----------')
            print('Protocol : %s' % proto)
     
            lport = scanner[host][proto].keys()
            for port in lport:
                if scanner[host][proto][port]['state'] == "open":
                    snmpInterfaceList.append(port)
                    snmpInterfaceList.append(scanner[host][proto][port]['state'])
                    print ('port : %s\tstate : %s'
                            % (port, scanner[host][proto][port]['state']))
                    snmp = nmap.PortScanner()
                    snmp.scan(host, arguments='-sU -p 161 --script snmp-interfaces')
                    print(snmp[host][proto][port]['script']['snmp-interfaces'])
                    cur.execute('''
                    INSERT INTO SNMP_Software_Enummeration (IP_Address, Protocol, Port_Number, Port_Status, Interfaces) VALUES (?, ?, ?, ?, ?)
                    ''', snmpInterfaceList)
                    conn.commit()
                else:
                    print("Port 161 (SNMP) not opened, can't perform SNMP Enumuration")


#SMTP Users Enumuration
def smtpUsers():
    smtpUsersList = []
    scanner = nmap.PortScanner()
    target = input("Enter IP Address: ")
    smtpUsersList.append(target)
    scanner.scan(target, arguments='-p 25')
    for host in scanner.all_hosts():
        print(host)
        for proto in scanner[host].all_protocols():
            smtpUsersList.append(proto)
            print('----------')
            print('Protocol : %s' % proto)
 
            lport = scanner[host][proto].keys()
            for port in lport:
                if scanner[host][proto][port]['state'] == "open":
                    smtpUsersList.append(port)
                    smtpUsersList.append(scanner[host][proto][port]['state'])
                    print ('port : %s\tstate : %s'
                            % (port, scanner[host][proto][port]['state']))
                    smtp = nmap.PortScanner()
                    smtp.scan(host, arguments='-p 25 --script smtp-enum-users')
                    print(smtp[host][proto][port]['script']['smtp-enum-users'])
                    cur.execute('''
                    INSERT INTO SMTP_User_Enummeration (IP_Address, Protocol, Port_Number, Port_Status, Users) VALUES (?, ?, ?, ?, ?)
                    ''', smtpUsersList)
                    conn.commit()
            else:
                print("Port 25 (SMTP) not opened, can't perform SMTP Enumuration")

#NFS Share Enumuration
def nfsShare():
    nfsShareList = []
    scanner = nmap.PortScanner()
    target = input("Enter IP Address: ")
    nfsShareList.append(target)
    scanner.scan(target, arguments='-p 2049')
    for host in scanner.all_hosts():
        print(host)
        for proto in scanner[host].all_protocols():
            nfsShareList.append(proto)
            print('----------')
            print('Protocol : %s' % proto)

            lport = scanner[host][proto].keys()
            for port in lport:
                if scanner[host][proto][port]['state'] == "open":
                    nfsShareList.append(port)
                    nfsShareList.append(scanner[host][proto][port]['state'])
                    print ('port : %s\tstate : %s'
                            % (port, scanner[host][proto][port]['state']))
                    smtp = nmap.PortScanner()
                    smtp.scan(host, arguments='-sV -p 2049 --script nfs-showmount')
                    print("\nnfs-showmount:")
                    print(smtp[host][proto][port]['script']['nfs-showmount'])
                    cur.execute('''
                    INSERT INTO NFS_Share_Enummeration (IP_Address, Protocol, Port_Number, Port_Status, Shares) VALUES (?, ?, ?, ?, ?)
                    ''', nfsShareList)
                    conn.commit()
            else:
                print("Port 2049 (NFS) not opened, can't perform NFS Enumuration")

def googleShare():
    toSearch = input("What do you want to search? ")
    print("\nResults:")
    for searchItem in search(toSearch, num=10, stop=10):
        print(searchItem)

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
    external_urls = set()
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
        pos = 0
        while len(in_list) > len(ex_list):
            ex_list.append("NULL")
            continue
        for i in in_list:
            list = [in_list[pos],ex_list[pos]]
            cur.execute('''
            INSERT INTO Spidering (Internal_URLs, External_URLs) VALUES (?,?)
            ''', list)
            conn.commit()
            pos += 1
            continue
        print("[+] Total Internal links:", len(internal_urls))
        print("[+] Total External links:", len(external_urls))
        print("[+] Total URLs:", len(external_urls) + len(internal_urls))

while loop == True:
    project_menu()
