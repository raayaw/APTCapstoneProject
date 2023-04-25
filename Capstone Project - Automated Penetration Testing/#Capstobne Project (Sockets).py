#Capstobne Project
#Members: Aw Jin Le Ray, Kim Junghan, Lucas Sim
import socket
import threading
def project_menu():
    print("This is Automated Pentesting.")
    print("\nPlease Select an Option Below.")
    print("Port scanning")
    print("Option 2")
    print("Option 3")
    print("Quit")
    menu_input = int()
    while menu_input == int():
        menu_input = int(input("Select option: "))
        if menu_input == 1:
            print("Option 1 Selected.")
            checkport()
        elif menu_input == 2:
            print("Option 2 Selected.")
            option_2()
        elif menu_input == 3:
            print("Option 3 Selected.")
            option_3()
        elif menu_input == 4:
            print("Option 4 Selected.")
            option_4()
        else:
            print("Invalid Input!\nPlease Try Again!")
            continue

def checkport():
    print("This is option 1 function")
    target = input("Enter an IP Address to scan: ")
    start_port = int(input("Enter starting port range here: "))
    end_port= int(input("Enter ending port range here: "))
    port_range = range(start_port, end_port+1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    for port in range(start_port,end_port):
        try:
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f"Port {port} is open")
            sock.close()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.01)
        except KeyboardInterrupt:
            print("Exiting...")
            break
        except socket.gaierror:
            print("Hostname could not be resolved")
            break
        except socket.error:
            print("Could not connect to server")
            break

    # threads = []

    # start = 50 #begining of list of ports to scan

    # end = 85 #end of list of ports to scan

    # ltype = list(range(start, end))

    # for x in ltype:
    #     t = threading.Thread(target=checkport, args=(x,))
    #     t.daemon = True
    #     threads.append(t)
    # for x in range(len(threads)):
    #     threads[x].start()
    # for x in range(len(threads)):
    #     threads[x].join()

def option_2():
    print("This is option 2 function")

def option_3():
    print("This is option 3 function")

def option_4():
    print("Goodbye")
    exit()

project_menu()
