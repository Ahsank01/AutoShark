"""
Contributer 1: Ahsan Khan
Contributer 2: Razu Ali
School: Fullstack Academy Here
Date: 07/17/2021
Project Name: AutoShark
Modules Used For This Project: ys, pyshark, scapy, re

Summary of this file: The file First_Option.py contains all the functions we created to get IP addresses, MAC addresses and TCP/UDP ports
"""

# Import scapy to parse data from a pcap file
from scapy.all import *
# Import regular expression to search for ip and mac
import re
# Import sys to get a file as a command line input
import sys


# This function will just return the raw content of a pcap file
def read_sys_argv():

    # Read the file as a command line argument, and save it to a variable file
    file = sys.argv[1]

    # return the content of the file
    return file


# This function will read each line at a time of a pcap file and save it to a list
def read_file():

    # Call the read_sys_argv() function and save the data to a variable called file
    file = read_sys_argv()

    # Read the pcap file using rdpcap
    pcap_file = rdpcap(file)

    # Empty list to save a content of a pcap file
    packet_list = []

    # Loop over the pcap file, one line at a time
    for data in pcap_file:

        # Decode the data and append it to a list
        packet_list.append(repr(data))

    # Return the list with pcap data
    return packet_list


# This function will only return the number of packets
def num_of_packets():

    # Call the function read_file() and save it to a variable
    packets = read_file()

    # Print the number of packers in a pcap file
    print(f"Number of Packets: {len(packets)}")


# This function get the IP and their counts from the source option
def set_src_ip():

    # Empty dictionary to save IP and their counts
    dictionary = {}

    # Call a function read_file() and save it to a variable
    packet_output = read_file()

    # Make a re expression to search for IP addresses in a pcap file
    src_ip = re.compile('src=([0-9]{1,3}\.){3}[0-9]{1,3}')

    # Loop over the pcap data list
    for packet in packet_output:

        # Search for the IP using the regex expression
        src_matches = src_ip.search(packet)

        # If the IP found
        if src_matches:

            # Group it
            match1 = src_matches.group()

            # Do split the match string based on '=' as the delimiter
            ip = match1.split('=')[1]

            # If the ip is not in the dictionary then add 1 to it
            if ip not in dictionary:
                dictionary[ip] = 1

            # If the ip is in the dictionary then increment it
            else:
                dictionary[ip] += 1

    # Return the dictionary of IP and their counts
    return dictionary


# This function get the IP and their counts from the destination option
def set_dst_ip():

    # Empty dictionary to save IP and their counts
    dictionary = {}

    # Call a function read_file() and save it to a variable
    packet_output = read_file()

    # Make a re expression to search for IP addresses in a pcap file
    dst_ip = re.compile('dst=([0-9]{1,3}\.){3}[0-9]{1,3}')

    # Loop over the pcap data list
    for packet in packet_output:

        # Search for the IP using the regex expression
        dst_matches = dst_ip.search(packet)

        # If the IP found
        if dst_matches:

            # Group it
            match1 = dst_matches.group()

            # Do split the match string based on '=' as the delimiter
            ip = match1.split('=')[1]

            # If the ip is not in the dictionary then add 1 to it
            if ip not in dictionary:
                dictionary[ip] = 1

            # If the ip is in the dictionary then increment it
            else:
                dictionary[ip] += 1

    # Return the dictionary of IP and their counts
    return dictionary


# This function will match the source ip to their mac with their tcp and udp ports
def match_src_ip_mac_TCP_UDP():

    # Make a re expression to search for IP addresses in a pcap file
    src_ip = re.compile('src=([0-9]{1,3}\.){3}[0-9]{1,3}')

    # Make a re expression to search for MAC addresses in a pcap file
    src_mac = re.compile('src=([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})')

    # Make a re expression to search for source ports in a pcap file
    sport = re.compile('sport=([0-9]{1,6}|[a-zA-Z]{1,25})')

    # Call read_file() function and save it to a variable
    packet_output = read_file()

    # Empty dictionary to save an IP and its MAC address and tcp udp ports
    ip_mac = {}

    # Variable to save IP address as a key for the dictionary
    ip = ' '

    # Loop over the packets list
    for packet in packet_output:

        # Check if the expression IP is in the packet, and if true,
        if "|<IP" in packet:

            # Search for ip address using a regex expression
            ip_matches = src_ip.search(packet)

            # Search for a mac address using a regex expression
            mac_matches = src_mac.search(packet)

            # If IP and MAC found
            if ip_matches and mac_matches:

                # Group IP
                match1 = ip_matches.group()

                # Group MAC
                match2 = mac_matches.group()

                # Do split the match string based on '=' as the delimiter
                ip = match1.split('=')[1]

                # Do split the match string based on '=' as the delimiter
                mac = match2.split('=')[1]

                # If IP not in the dictionary
                if ip not in ip_mac:

                    # Save IP as a key and MAC as a value
                    ip_mac[ip] = {'MAC':mac,'TCP':[],'UDP':[]}

        # Check if the expression TCP is in the packet, if true
        if "|<TCP" in packet:

            # Search for a TCP port using a regex expression
            sport_matches = sport.search(packet)

            # If port found
            if sport_matches:

                # If port found
                match = sport_matches.group()

                # Do split the match string based on '=' as the delimiter
                port = match.split('=')[1]

                # If  port not in a dictionary, make a key called TCP
                if port not in ip_mac[ip]['TCP']:

                    # If the port is not NULL
                    if port != '':

                        # Save port as a value for TCP, and append it to a dictionary
                        ip_mac[ip]['TCP'].append(port)

        # Check if the expression UDP is in the packet, if true
        if "|<UDP" in packet:

            # Search for a TCP port using a regex expression
            sport_matches = sport.search(packet)

            # If port found
            if sport_matches:

                # If port found
                match = sport_matches.group()

                # Do split the match string based on '=' as the delimiter
                port = match.split('=')[1]

                # If  port not in a dictionary, make a key called TCP
                if port not in ip_mac[ip]['UDP']:

                    # If the port is not NULL
                    if port != '':

                        # Save port as a value for TCP, and append it to a dictionary
                        ip_mac[ip]['UDP'].append(port)

    # Sort the TCP ports in the reverse option
    ip_mac[ip]['TCP'].sort(reverse=True)

    # Sort the UDP ports in the reverse option
    ip_mac[ip]['UDP'].sort(reverse=True)

    # Return a dictionary that contains IP, MAC, TCP/UDP Ports
    return ip_mac


# This function will match the source ip to their mac with their tcp and udp ports
def match_dst_ip_mac_TCP_UDP():

    # Make a re expression to search for IP addresses in a pcap file
    dst_ip = re.compile('dst=([0-9]{1,3}\.){3}[0-9]{1,3}')

    # Make a re expression to search for MAC addresses in a pcap file
    dst_mac = re.compile('dst=([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})')

    # Make a re expression to search for source ports in a pcap file
    dport = re.compile('dport=([0-9]{1,6}|[a-zA-Z]{1,25})')

    # Call read_file() function and save it to a variable
    packet_output = read_file()

    # Empty dictionary to save an IP and its MAC address and tcp udp ports
    ip_mac = {}

    # Variable to save IP address as a key for the dictionary
    ip = ' '

    # Loop over the packets list
    for packet in packet_output:

        # Check if the expression IP is in the packet, and if true,
        if "|<IP" in packet:

            # Search for ip address using a regex expression
            ip_matches = dst_ip.search(packet)

            # Search for a mac address using a regex expression
            mac_matches = dst_mac.search(packet)

            # If IP and MAC found
            if ip_matches and mac_matches:

                # Group IP
                match1 = ip_matches.group()

                # Group MAC
                match2 = mac_matches.group()

                # Do split the match string based on '=' as the delimiter
                ip = match1.split('=')[1]

                # Do split the match string based on '=' as the delimiter
                mac = match2.split('=')[1]

                # If IP not in the dictionary
                if ip not in ip_mac:
                    # Save IP as a key and MAC as a value
                    ip_mac[ip] = {'MAC': mac, 'TCP': [], 'UDP': []}

        # Check if the expression TCP is in the packet, if true
        if "|<TCP" in packet:

            # Search for a TCP port using a regex expression
            dport_matches = dport.search(packet)

            # If port found
            if dport_matches:

                # If port found
                match = dport_matches.group()

                # Do split the match string based on '=' as the delimiter
                port = match.split('=')[1]

                # If  port not in a dictionary, make a key called TCP
                if port not in ip_mac[ip]['TCP']:

                    # If the port is not NULL
                    if port != '':
                        # Save port as a value for TCP, and append it to a dictionary
                        ip_mac[ip]['TCP'].append(port)

        # Check if the expression UDP is in the packet, if true
        if "|<UDP" in packet:

            # Search for a TCP port using a regex expression
            dport_matches = dport.search(packet)

            # If port found
            if dport_matches:

                # If port found
                match = dport_matches.group()

                # Do split the match string based on '=' as the delimiter
                port = match.split('=')[1]

                # If  port not in a dictionary, make a key called TCP
                if port not in ip_mac[ip]['UDP']:

                    # If the port is not NULL
                    if port != '':
                        # Save port as a value for TCP, and append it to a dictionary
                        ip_mac[ip]['UDP'].append(port)

    # Sort the TCP ports in the reverse option
    ip_mac[ip]['TCP'].sort(reverse=True)

    # Sort the UDP ports in the reverse option
    ip_mac[ip]['UDP'].sort(reverse=True)

    # Return a dictionary that contains IP, MAC, TCP/UDP Ports
    return ip_mac


# This function will print all he IPs and its information
def everything():

    # Call the function everything_from_source()
    everything_from_source()

    # Call the function everything_from_destination()
    everything_from_destination()


# This function is to print everything from the source
def everything_from_source():

    # Call set_src_ip() function and save it to a variable
    src_ip_count = set_src_ip()

    # Call match_src_ip_mac_TCP_UDP() function and save it to a variable
    src = match_src_ip_mac_TCP_UDP()

    # Print source details
    print("--------------------")
    print("| SOURCE DETAIL(s) |")
    print("--------------------")

    # Count variable to make a list of 3
    count = 1

    # Loop over the dictionary items
    for k1, v1 in src.items():

        # Print the IP string
        print("(" + str(count) + ") IP:", end=' ')

        # Print the IP Address
        print(k1, end='\t')

        # Nested Loop
        for k2, v2 in v1.items():

            # Check if the check is MAC, if true
            if k2 == 'MAC':

                # Print MAC string
                print("\n     MAC:", end=' ')

                # Print MAC value
                print(v2)

            # Check if the key is TCP, if true
            if k2 == 'TCP':

                # Print the TCP String
                print("\t> TCP PORT(s):", end=' ')

                # If no TCP Ports
                if v2 == []:

                    # Print this
                    print('No port on this protocol')

                # Otherwise, check the length of the list
                elif len(v2) > 9:

                    # Make a variable to increment in the while loop
                    i = 0

                    # While i is less than 10
                    # Print the first 10 ports
                    while i < 10:

                        # Print the port
                        print(v2[i], end= ' ')

                        # Add 1 to i
                        i += 1

                    # Newline
                    print()

                # Otherwise, print all the ports
                else:

                    # Loop over the tcp ports value
                    for tport in v2:

                        # Print one at a time
                        print(tport, end=' ')

                    # Newline
                    print()

            # Check if the key is UDP, if true
            if k2 == 'UDP':

                # Print the UDP String
                print("\t> UDP PORT(s):", end=' ')

                # If no TCP Ports
                if v2 == []:

                    # Print this
                    print('No port on this protocol')

                # Otherwise, check the length of the list
                elif len(v2) > 9:

                    # Make a variable to increment in the while loop
                    i = 0

                    # While i is less than 10
                    # Print the first 10 ports
                    while i < 5:

                        # Print the port
                        print(v2[i], end=' ')

                        # Add 1 to i
                        i += 1

                    # Newline
                    print()

                # Otherwise, print all the ports
                else:

                    # Loop over the tcp ports value
                    for uport in v2:

                        # Print one at a time
                        print(uport, end=' ')

                    # Newline
                    print()

        # Loop over the keys of the dictionary
        if k1 in src_ip_count.keys():

            # Print the string IP Count
            print("\t> IP COUNT:", end=' ')

            # Print the key
            print(src_ip_count[k1])

            # Newline
            print()

        # Increment the count
        count += 1


# This function is to print everything from the destination
def everything_from_destination():

    # Call set_dst_ip() function and save it to a variable
    dst_ip_count = set_dst_ip()

    # Call match_src_ip_mac_TCP_UDP() function and save it to a variable
    dst = match_dst_ip_mac_TCP_UDP()

    # Print source details
    print("-------------------------")
    print("| DESTINATION DETAIL(s) |")
    print("-------------------------")

    # Count variable to make a list of 3
    count = 1

    # Loop over the dictionary items
    for k1, v1 in dst.items():

        # Print the IP string
        print("(" + str(count) + ") IP:", end=' ')

        # Print the IP Address
        print(k1, end='\t')

        # Nested Loop
        for k2, v2 in v1.items():

            # Check if the check is MAC, if true
            if k2 == 'MAC':

                # Print MAC string
                print("\n     MAC:", end=' ')

                # Print MAC value
                print(v2)

            # Check if the key is TCP, if true
            if k2 == 'TCP':

                # Print the TCP String
                print("\t> TCP PORT(s):", end=' ')

                # If no TCP Ports
                if v2 == []:

                    # Print this
                    print('No port on this protocol')

                # Otherwise, check the length of the list
                elif len(v2) > 9:

                    # Make a variable to increment in the while loop
                    i = 0

                    # While i is less than 10
                    # Print the first 10 ports
                    while i < 10:

                        # Print the port
                        print(v2[i], end=' ')

                        # Add 1 to i
                        i += 1

                    # Newline
                    print()

                # Otherwise, print all the ports
                else:

                    # Loop over the tcp ports value
                    for tport in v2:

                        # Print one at a time
                        print(tport, end=' ')

                    # Newline
                    print()

            # Check if the key is UDP, if true
            if k2 == 'UDP':

                # Print the UDP String
                print("\t> UDP PORT(s):", end=' ')

                # If no UDP Ports
                if v2 == []:

                    # Print this
                    print('No port on this protocol')

                # Otherwise, check the length of the list
                elif len(v2) > 9:

                    # Make a variable to increment in the while loop
                    i = 0

                    # While i is less than 10
                    # Print the first 10 ports
                    while i < 10:

                        # Print the port
                        print(v2[i], end=' ')

                        # Add 1 to i
                        i += 1

                    # Newline
                    print()

                # Otherwise, print all the ports
                else:

                    # Loop over the tcp ports value
                    for uport in v2:

                        # Print one at a time
                        print(uport, end=' ')

                    # Newline
                    print()

        # Loop over the keys of the dictionary
        if k1 in dst_ip_count.keys():

            # Print the string IP Count
            print("\t> IP COUNT:", end=' ')

            # Print the string IP Count
            print(dst_ip_count[k1])

            # Newline
            print()

        # Increment the count
        count += 1

# -- #


# get all the ips and save it to a list
def set_all_ip():

    # Call set_dst_ip() function and save it to a variable
    dst_ip = set_dst_ip()

    # Call set_src_ip() function and save it to a variable
    src_ip = set_src_ip()

    # Make an empty list to save all IPs
    all_ip = []

    # Loop over the keys of the dictionary of destination IP
    for key in dst_ip.keys():

        # Check if the key is already in the list, if not
        if key not in all_ip:
            # Append key of the dictionary, to a list
            all_ip.append((key))
        else:
            continue

    # Loop over the keys of the dictionary of source IP
    for key in src_ip.keys():

        # Check if the key is already in the list, if not
        if key not in all_ip:

            # Append key of the dictionary, to a list
            all_ip.append(key)

        else:
            continue

    # Return a list of all the IPs
    return all_ip


# This function will print all the IP address found on a pcap file, that includes source and destination IP Addresses
def get_all_ip():

    # This variable will increment the count of IPs
    count = 1

    # Call the function set_all_ip() and reverse sort it
    ips = sorted(set_all_ip(), key=None, reverse=True)

    # Call set_src_ip() function and save it to a variable
    src_ip = set_src_ip()

    # Call set_dst_ip() function and save it to a variable
    dst_ip = set_dst_ip()

    # Print all the IPs
    print("All the IP Addresses found in the PCAP file:")

    # Loop over the IP list
    for ip in ips:

        # Check if the IP is both in source and destination, if true
        if (ip in src_ip) and (ip in dst_ip):

            # Print the total count of the IP from source and destination
            print(f"{count}. {ip} => {src_ip[ip] + dst_ip[ip]}")

        # Check if the IP is only in source
        elif ip in src_ip:

            # Print the total count of the IP from source
            print(f"{count}. {ip} => {src_ip[ip]}")

        # Otherwise get the IP from destination
        else:

            # Print the total count of the IP from destination
            print(f"{count}. {ip} => {dst_ip[ip]}")

        # Increment the count
        count += 1


# This function will only print the Source IP addresses found in a pcap file
def get_all_src_ip():
    # Call set_dst_ip() function and save it here
    ips = set_src_ip()

    # An empty list to save all the destination ips
    src_ip = []

    # Use this variable to increment the count of Ips
    count = 1

    # Loop over the keys in a dictionary
    for key in ips.keys():
        # Append the key into a list
        src_ip.append(key)

    # Reverse sort the list
    src_ip = sorted(src_ip, key=None, reverse=True)

    # Print all the ips
    print("ALL THE SOURCE IP ADDRESSES AND THEIR COUNT AS A DESTINATION IP")

    # Loop over the IP List
    for ip in src_ip:
        # Print IP and its count, one at a time
        print(f"{count}. {ip} => {ips[ip]}")

        # Increment the count of IPs
        count += 1


# This function will only print the Destination IP addresses found in a pcap file
def get_all_dst_ip():

    # Call set_dst_ip() function and save it here
    ips = set_dst_ip()

    # An empty list to save all the destination ips
    dst_ip = []

    # Use this variable to increment the count of Ips
    count = 1

    # Loop over the keys in a dictionary
    for key in ips.keys():

        # Append the key into a list
        dst_ip.append(key)

    # Reverse sort the list
    dst_ip = sorted(dst_ip, key=None, reverse=True)

    # Print all the ips
    print("ALL THE DESTINATION IP ADDRESSES AND THEIR COUNT AS A DESTINATION IP")

    # Loop over the IP List
    for ip in dst_ip:

        # Print IP and its count, one at a time
        print(f"{count}. {ip} => {ips[ip]}")

        # Increment the count of IPs
        count += 1


# This function will get all the source MAC addresses
def set_src_mac():

    # Empty dictionary to save MAC addresses and their counts
    dictionary = {}

    # Call read_file() function and save it to a variable
    packet_output = read_file()

    # Make a regex expression to search for MAC address in a pcap file
    src_mac = re.compile('src=([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})')

    # Loop over the lists of packets
    for packet in packet_output:

        # Search for the MAC address
        src_matches = src_mac.search(packet)

        # If found
        if src_matches:

            # Group it
            match1 = src_matches.group()

            # Do split the match string based on '=' as the delimiter
            mac = match1.split('=')[1]

            # If the ip is not in the dictionary then add 1 to it
            if mac not in dictionary:
                dictionary[mac] = 1

            # If the ip is in the dictionary then increment it
            else:
                dictionary[mac] += 1

    # Return the dictionary of Mac and their counts
    return dictionary


# This function will get all the destination MAC addresses
def set_dst_mac():

    # Empty dictionary to save MAC addresses and their counts
    dictionary = {}

    # Call read_file() function and save it to a variable
    packet_output = read_file()

    # Make a regex expression to search for MAC address in a pcap file
    dst_mac = re.compile('dst=([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})')

    # Loop over the lists of packets
    for packet in packet_output:

        # Search for the MAC address
        dst_matches = dst_mac.search(packet)

        # If found
        if dst_matches:

            # Group it
            match1 = dst_matches.group()

            # Do split the match string based on '=' as the delimiter
            mac = match1.split('=')[1]

            # If the ip is not in the dictionary then add 1 to it
            if mac not in dictionary:
                dictionary[mac] = 1

            # If the ip is in the dictionary then increment it
            else:
                dictionary[mac] += 1

    # Return the dictionary of Mac and their counts
    return dictionary


# This function will get all the source ip and their mac addresses
def match_src_ip_and_mac():

    # Empty dictionary to save an IP and its MAC address and tcp udp ports
    ip_mac = {}

    # Call read_file() function and save it to a variable
    packet_output = read_file()

    # Make a re expression to search for IP addresses in a pcap file
    src_ip = re.compile('src=([0-9]{1,3}\.){3}[0-9]{1,3}')

    # Make a re expression to search for MAC addresses in a pcap file
    src_mac = re.compile('src=([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})')

    # Variable to save IP address as a key for the dictionary

    # Loop over the packets list
    for packet in packet_output:

        # Check if the expression IP is in the packet, and if true,
        if "|<IP" in packet:

            # Search for ip address using a regex expression
            ip_matches = src_ip.search(packet)

            # Search for a mac address using a regex expression
            mac_matches = src_mac.search(packet)

            # If IP and MAC found
            if ip_matches and mac_matches:

                # Group IP
                match1 = ip_matches.group()

                # Group MAC
                match2 = mac_matches.group()

                # Do split the match string based on '=' as the delimiter
                ip = match1.split('=')[1]

                # Do split the match string based on '=' as the delimiter
                mac = match2.split('=')[1]

                # If IP not in the dictionary
                if ip not in ip_mac:

                    # Save IP as a key and MAC as a value
                    ip_mac[ip] = mac

                # Ignore
                else:
                    pass

    # Return a dictionary with ip and its mac
    return ip_mac


# This function will get all the destination ip and their mac addresses
def match_dst_ip_and_mac():

    # Empty dictionary to save an IP and its MAC address and tcp udp ports
    ip_mac = {}

    # Call read_file() function and save it to a variable
    packet_output = read_file()

    # Make a re expression to search for IP addresses in a pcap file
    dst_ip = re.compile('dst=([0-9]{1,3}\.){3}[0-9]{1,3}')

    # Make a re expression to search for MAC addresses in a pcap file
    dst_mac = re.compile('dst=([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})')

    # Variable to save IP address as a key for the dictionary

    # Loop over the packets list
    for packet in packet_output:

        # Check if the expression IP is in the packet, and if true,
        if "|<IP" in packet:

            # Search for ip address using a regex expression
            ip_matches = dst_ip.search(packet)

            # Search for a mac address using a regex expression
            mac_matches = dst_mac.search(packet)

            # If IP and MAC found
            if ip_matches and mac_matches:

                # Group IP
                match1 = ip_matches.group()

                # Group MAC
                match2 = mac_matches.group()

                # Do split the match string based on '=' as the delimiter
                ip = match1.split('=')[1]

                # Do split the match string based on '=' as the delimiter
                mac = match2.split('=')[1]

                # If IP not in the dictionary
                if ip not in ip_mac:

                    # Save IP as a key and MAC as a value
                    ip_mac[ip] = mac

                # Ignore
                else:
                    pass

    # Return a dictionary with ip and its mac
    return ip_mac


# This function will get all the TCP and UDP ports from the SOURCE IP
def source_ports():

    # Empty dictionary to save tcp and udp ports
    s_ports = {}

    # Make key for a dict called, TCP
    s_ports['TCP'] = []

    # Make key for a dict called, UDP
    s_ports['UDP'] = []

    # Call read_file() function and save it to a variable
    packet_output = read_file()

    # Make a regex expression to look for destination ports
    sport = re.compile('sport=([0-9]{0,6}|[a-zA-Z]{1-25})')

    # Loop over the list of packets
    for packet in packet_output:

        # Check if the expression TCP is in the packet, if true
        if "|<TCP" in packet:

            # Search for it
            sport_matches = sport.search(packet)

            # If found
            if sport_matches:

                # Group it
                match = sport_matches.group()

                # Do split the match string based on '=' as the delimiter
                port = match.split('=')[1]

                # If port not in TCP value
                if port not in s_ports['TCP']:

                    # If port not equal to NULL value
                    if port != '':
                        # Save port as a value for tcp
                        s_ports['TCP'].append(port)

        # Check if the expression UDP is in the packet, if true
        elif "|<UDP" in packet:

            # Search for it
            sport_matches = sport.search(packet)

            # If found
            if sport_matches:

                # Group it
                match = sport_matches.group()

                # Do split the match string based on '=' as the delimiter
                port = match.split('=')[1]

                # If port not in UDP value
                if port not in s_ports['UDP']:

                    # If port not equal to NULL value
                    if port != '':
                        # Save port as a value for udp
                        s_ports['UDP'].append(port)

    # Sort the TCP ports in the reverse option
    s_ports['TCP'].sort(reverse=True)

    # Sort the UDP ports in the reverse option
    s_ports['UDP'].sort(reverse=True)

    # Return the ports dictionary
    return s_ports


# This function will get all the TCP and UDP ports from the DESTINATION IP
def destination_ports():

    # Empty dictionary to save tcp and udp ports
    d_ports = {}

    # Make key for a dict called, TCP
    d_ports['TCP'] = []

    # Make key for a dict called, UDP
    d_ports['UDP'] = []

    # Call read_file() function and save it to a variable
    packet_output = read_file()

    # Make a regex expression to look for destination ports
    dport = re.compile('dport=([0-9]{0,6}|[a-zA-Z]{1-25})')

    # Loop over the list of packets
    for packet in packet_output:

        # Check if the expression TCP is in the packet, if true
        if "|<TCP" in packet:

            # Search for it
            dport_matches = dport.search(packet)

            # If found
            if dport_matches:

                # Group it
                match = dport_matches.group()

                # Do split the match string based on '=' as the delimiter
                port = match.split('=')[1]

                # If port not in TCP value
                if port not in d_ports['TCP']:

                    # If port not equal to NULL value
                    if port != '':

                        # Save port as a value for tcp
                        d_ports['TCP'].append(port)

        # Check if the expression UDP is in the packet, if true
        elif "|<UDP" in packet:

            # Search for it
            dport_matches = dport.search(packet)

            # If found
            if dport_matches:

                # Group it
                match = dport_matches.group()

                # Do split the match string based on '=' as the delimiter
                port = match.split('=')[1]

                # If port not in UDP value
                if port not in d_ports['UDP']:

                    # If port not equal to NULL value
                    if port != '':

                        # Save port as a value for udp
                        d_ports['UDP'].append(port)

    # Sort the TCP ports in the reverse option
    d_ports['TCP'].sort(reverse=True)

    # Sort the UDP ports in the reverse option
    d_ports['UDP'].sort(reverse=True)

    # Return the ports dictionary
    return d_ports
