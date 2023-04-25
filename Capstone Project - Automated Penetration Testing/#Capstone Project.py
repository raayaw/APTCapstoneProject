#Capstobne Project
#Members: Aw Jin Le Ray, Kim Junghan, Lucas Sim
import nmap
loop = True
def project_menu():
    print("This is Automated Pentesting.")
    print("\nPlease Select an Option Below.")
    print("1. Port scanning")
    print("Option 2")
    print("Option 3")
    print("4. Quit")
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
            print("Goodbye.")
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
    scanner.scan(target, arguments='-O')
    if scanner[target]['osmatch']:
        print('Operating System: ' + scanner[target]['osmatch'][0]['name'])
    else:
        print('Failed to determine operating system')
    for host in scanner.all_hosts():
        print(f"Host: {host}")
        for port in scanner[host]['tcp']:
            state = scanner[host]['tcp'][port]['state']
            print(f"Port {port} is {state}")


def option_2():
    print("This is option 2 function")

def option_3():
    print("This is option 3 function")

def option_4():
    exit()
while loop == True:
    project_menu()
