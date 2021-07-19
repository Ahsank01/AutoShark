"""
Contributer 1: Ahsan Khan
Contributer 2: Razu Ali
School: Fullstack Academy Here
Date: 07/17/2021
Project Name: AutoShark
Modules Used For This Project: ys, pyshark, scapy, re

Summary of this file: The file Auto_shark.py is the main file that runs the program and prompt all the options to the user.
The file contains 4 options, and 3 sub options.
"""

#!/usr/bin/python3
# CODE FOR AUTO SHARK

# Import all the functions from First_Option.py
from First_Option import *
# Import all the functions from Second_Option.py
from Second_Option import *
# Import all the functions from Third_Option.py
from Third_Option import *
#Import all the functions from Fourth_Option.py
from Fourth_Option import *


# This function is o make the intro heading red in color.
def colored(r, g, b, text):
    return "\033[38;2;{};{};{}m{} \033[38;2;255;255;255m".format(r, g, b, text)


# The intro function will only print the name of the program
def intro():
    print(colored(255, 0, 0, """
         .8.       8 8888      88 8888888 8888888888 ,o888888o.       d888888o.   8 8888        8          .8.          8 888888888o.   8 8888     ,88' 
        .888.      8 8888      88       8 8888    . 8888     `88.   .`8888:' `88. 8 8888        8         .888.         8 8888    `88.  8 8888    ,88'  
       :88888.     8 8888      88       8 8888   ,8 8888       `8b  8.`8888.   Y8 8 8888        8        :88888.        8 8888     `88  8 8888   ,88'   
      . `88888.    8 8888      88       8 8888   88 8888        `8b `8.`8888.     8 8888        8       . `88888.       8 8888     ,88  8 8888  ,88'    
     .8. `88888.   8 8888      88       8 8888   88 8888         88  `8.`8888.    8 8888        8      .8. `88888.      8 8888.   ,88'  8 8888 ,88'     
    .8`8. `88888.  8 8888      88       8 8888   88 8888         88   `8.`8888.   8 8888        8     .8`8. `88888.     8 888888888P'   8 8888 88'      
   .8' `8. `88888. 8 8888      88       8 8888   88 8888        ,8P    `8.`8888.  8 8888888888888    .8' `8. `88888.    8 8888`8b       8 888888<       
  .8'   `8. `88888.` 8888     ,8P       8 8888   `8 8888       ,8P 8b   `8.`8888. 8 8888        8   .8'   `8. `88888.   8 8888 `8b.     8 8888 `Y8.     
 .888888888. `88888. 8888   ,d8P        8 8888    ` 8888     ,88'  `8b.  ;8.`8888 8 8888        8  .888888888. `88888.  8 8888   `8b.   8 8888   `Y8.   
.8'       `8. `88888. `Y88888P'         8 8888       `8888888P'     `Y8888P ,88P' 8 8888        8 .8'       `8. `88888. 8 8888     `88. 8 8888     `Y8. """))


# This function will output a greeting heading
def greet():
    print("\nWelcome to AutoShark")


# This function will prompt the user with all the options that are in this tool
def menu():
    print("""\nPlease select from the following options:
	1- Extract IP:
	2- All Type of File(s)
	3- Indicators of Compromise
	4- Save to a File
	""")


# This function will receive a user input from the menu
def get_choice():

    # This list will be used to verify that the user does not enter anything except 1,2,3,4.
    option = ['1', '2', '3', '4']

    # Keep the loop running, until the user does not enter a proper number between 1 - 4
    while True:
        # Receive an input from the user
        choice = input("Choice: ")
        # Once we get the input from the user, we use isnumeric() function to confirm if the input is a number string or alpha string
        if choice.isnumeric():
            # if it is a number string, then we run this code
            if choice in option:
                return choice
            # Otherwise output a string saying you broke it
            else:
                print("YOU BROKE IT\n")
                # If the user does not enter a proper input, ask the user for the option again
                continue
        # If a user does not enter a number, output you broke it, and then run the code again
        else:
            print("YOU BROKE IT\n")
            continue


# Use this function to prompt the user if they want to use the program again
def prompt_again():
    # Ask user for there input if they wanna try again
    answer = input("\nWould you like to do something else (Y/N): ")
    # return the answer as a lower case (y n)
    return answer.lower()


# Simple function to say Goodbye
def bye():
    print("\nGoodbye")


# This function will loop through the different options
def loop():
    # Keep running the code, until the user dont wanna quit.
    while True:
        # calling the menu() function here to print the menu()
        menu()
        # calling the get_choice() function here to get the user input and store it into a 'value' variable
        value = get_choice()

        # If the user enters 1, prompt the user with 3 sub options
        if value == '1':
            print("\tA: Get ALL the information of the IP(s)")
            print("\tB: Get ALL the information of the SOURCE IP(s) ONLY")
            print("\tC: Get ALL the information of the DESTINATION IP(s) ONLY")
            # Receive an input from a user in a form of A or B
            sub_answer = input("\nChoice: ")

            # If the user enters A
            if (sub_answer == 'A') or (sub_answer == 'a'):
                # Run this code
                num_of_packets()
                everything()

            # If the user enters B
            elif (sub_answer == 'B') or (sub_answer == 'b'):
                # Run this code
                everything_from_source()

            # If the user enters C
            elif (sub_answer == 'C') or (sub_answer == 'c'):
                # Run this code
                everything_from_destination()

            # If the option does not exist
            else:
                # Run this code
                print("Option does not exist!!!")

            #prompt the user to see if they would like to do something else
            prompt = prompt_again()

            # If the user enters Y or y
            if prompt == 'y':
                # Continue everything again
                continue

            # Otherwise
            else:
                # End the program
                bye()
                break

        # If the user enters 2
        elif value == '2':
            # Run this code
            print("You chose to extract all type of file(s)\n")
            extractfiles()

            # prompt the user to see if they would like to do something else
            prompt = prompt_again()

            # If the user enters Y or y
            if prompt == 'y':
                # Continue everything again
                continue

            # Otherwise
            else:
                # End the program
                bye()
                break

        # If the user enters 3
        elif value == '3':
            # Run this code
            print("You chose to display indicators of compromise(IOC)\n")
            runit()

            # prompt the user to see if they would like to do something else
            prompt = prompt_again()

            # If the user enters Y or y
            if prompt == 'y':
                # Continue everything again
                continue

            # Otherwise
            else:
                # End the program
                bye()
                break

        # If the user enters 4
        elif value == '4':
            # Run this code
            print("You chose to save to a output file\n")
						do_this()

            # prompt the user to see if they would like to do something else
            prompt = prompt_again()

            # If the user enters Y or y
            if prompt == 'y':
                # Continue everything again
                continue

            # Otherwise
            else:
                # End the program
                bye()
                break

# First call the function intro()
intro()
# Then call greet()
greet()
# Then call loop()
loop()