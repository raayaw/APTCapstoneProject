#Capstobne Project
#Members: Aw Jin Le Ray, Kim Junghan, Lucas Sim
import sys
import nmap
import shodan
import sqlite3
from sqlite3 import Error
import pyfiglet
import scrapy
from scrapy.spiders import CrawlSpider, Rule
from scrapy.linkextractors import LinkExtractor

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
            spider()
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

def spider():
    class CrawlingSpider(CrawlSpider):
        name = "Spider"
        # Spider_URL = str(input("Enter URL to Spider here: "))
        allowed_domains = ["toscrape.com"]
        start_urls = ["http://CEH.com"]

        # rules = (
        #     Rule(LinkExtractor(allow="catalogue/category")),
        # )

while loop == True:
    project_menu()
