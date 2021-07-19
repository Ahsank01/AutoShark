"""
Contributer 1: Ahsan Khan
Contributer 2: Razu Ali
School: Fullstack Academy Here
Date: 07/17/2021
Project Name: AutoShark
Modules Used For This Project: ys, pyshark, scapy, re

Summary of this file: The file Second_Option.py contains all the code we wrote to find the types of file in a pcap file.
"""

# Import read_sys_argv() function from First_Option.py
from First_Option import read_sys_argv

# Import scapy to find files in a pcap file
from scapy.all import *


# This function is used to extract all kind of files from a pcap file
def extractfiles():

    # Call read_sys_argv() function and save it to a variable
    pcap = rdpcap(read_sys_argv())

    # Empty list to save the decoded packets
    decoded_list = []


    #method = ['GET', 'POST', 'PUT', 'MGET', 'STOR']

    # List to save all the files
    k = []

    # Dictionary to save the files and their counts
    s = {}

    # Regex expression to look for the extensions of a file
    regex = re.compile('.*\.(jpg|JPG|gif|GIF|jpeg|php|pdf|txt)')

    # Loop over the packets, one line at a time
    for pkt in pcap:

        # If Raw in pkt
        if Raw in pkt:

            # Assign pkt to p
            p = repr(pkt[Raw])

            # Append it to a list
            decoded_list.append(p)

    # Loop over the decoded packets list
    for line in decoded_list:

        # Search for the files using regex expressions
        matches = regex.search(line)

        # If found
        if matches:

            # Group it
            match1 = matches.group()

            # If the file is not in the k list
            if match1 not in k:

                # Split it, then append it to a list
                k.append(match1.split())

            # Otherwise Pass it
            else:
                pass

    # Loop over the K dictionary
    for l in k:

        # Nested loop for l
        for x in l:

            # Search using the regex expression
            matches = regex.search(x)

            # If found
            if matches:

                # Group it
                match1 = matches.group()

                # Check if \\ is in the match1, if true
                if '\\' in match1:

                    # Split the data with \\
                    j = match1.split('\\')

                    # Get the last value of j
                    match1 = j[-1]

                    # If match1 not in a dictionary
                    if match1 not in s:

                        # Save it, and add 1 to it
                        s[match1] = 1

                    # Otherwise
                    else:

                        # Add 1 to the value
                        s[match1] += 1

                # Search of / is in the match1, if true
                elif '/' in match1:

                    # Split it using /
                    j = match1.split('/')

                    # Get the last value of j
                    match1 = j[-1]

                    # If match1 is not in the dictionary
                    if match1 not in s:

                        # Save it, and add 1 to it
                        s[match1] = 1

                    # Otherwise
                    else:

                        # Add 1 to it
                        s[match1] += 1

                # Check if load=' is in the match1, if true
                elif "load='" in match1:

                    # Split it from '
                    j = match1.split("'")

                    # Get the last value of j
                    match1 = j[-1]

                    # If match1 is not in the dictionary
                    if match1 not in s:

                        # Save it, add 1 to it
                        s[match1] = 1

                    # Otherwise
                    else:

                        # Add 1 to it
                        s[match1] += 1

                # Otherwise
                else:

                    # If match1 not in the dictionary
                    if match1 not in s:

                        # Save it, add 1 to it
                        s[match1] = 1

                    # Otherwise
                    else:

                        # Add 1 to it
                        s[match1] += 1

    # Print it
    print('Found these image(s) and executable file(s) in the pcap:')
    print('Name => Occurrence(s)')

    # Loop over the dictionary
    for k, v in s.items():

        # Print key and value
        print(k, '=>', v)

    # Print the output
    print("There are about " + str(len(s)) + " images and executable in this pcap file.")