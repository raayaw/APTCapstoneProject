#Capstobne Project
#Members: Aw Jin Le Ray, Kim Junghan, Lucas Sim
import nmap
import shodan
import sqlite3
from sqlite3 import Error

#Shodan API KEY
Shodan_APIKEY = 'EBeU0lGqtIO6yCxVFCWC4nUVbvovtjo5'
api = shodan.Shodan(Shodan_APIKEY)
loop = True
def project_menu():
    print("This is Automated Pentesting.")
    print("\nPlease Select an Option Below.")
    print("1. Port scanning")
    print("Option 2")
    print("Option 3")
    print("4. OS Scan")
    menu_input = int()
    while menu_input == int():
        menu_input = int(input("Select option: "))
        if menu_input == 1:
            print("Option 1 Selected.")
            option_1()
        elif menu_input == 2:
            print("Option 2 Selected.")
            option_2()
        elif menu_input == 3:
            print("Option 3 Selected.")
            option_3()
        elif menu_input == 4:
            option_4()
        else:
            print("Invalid Input!\nPlease Try Again!")
            continue

def option_1():
    print("This is option 1 function")
    target = input("Enter an IP Address to scan: ")
    port_range = input("Enter the range of ports to scan (eg. 1-1024): ")
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
                 print ('port : %s\tstate : %s' % (port, scanner[host][proto][port]['state']))


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

def sqlite():
    try:
        conn = sqlite3.connect("APTdatabase.db")
        cur = conn.cursor()
        print("Successfully Connected to APTdatabase")


        conn.execute('''CREATE TABLE IF NOT EXISTS PortScanningTable
                        (port_number TEXT, port_status TEXT)''')
        
        conn.commit()

        ports = [("80", "open"), ("443", "closed"), ("", "")]
        cur.executemany('''
                        INSERT INTO PortScanningTable (port_number, port_status) VALUES (?, ?)
                        ''', ports)
        conn.commit()

    except sqlite3.Error as error:
        print("Failed to insert data into sqlite table", error)
    finally:
        if conn:
            cur.close()
            conn.close()
            print("The SQLite connection is closed")

sqlite()

while loop == True:
    project_menu()
