#Capstone Project
#Members: Aw Jin Le Ray, Kim Junghan, Lucas Sim

def project_menu():
    print("This is Automated Pentesting.")
    print("\nPlease Select an Option Below.")
    print("Port scanning")
    print("Option 2")
    print("Option 3")
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
        else:
            print("Invalid Input!\nPlease Try Again!")
            continue


project_menu()

