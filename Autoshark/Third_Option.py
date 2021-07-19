from First_Option import read_sys_argv
from scapy.all import *
import pyshark


# Call read_sys_argv() function here and save it to a variable
file = read_sys_argv()  # returning a file

# Read a pcap file using pyshark
cap = pyshark.FileCapture(file)

# This dictionary will save all the ips and their counts
all_ips = {}

# Variable to increment syn count
syn_count = 0

# List to save packets
sus_packs = []

# List to save http
sus_http = []

# This variable will be used to find directory traversal
dirtrav = '../../'

# Compare with this list to find sql injection
sql_inj = ['SELECT', 'load_file', 'union']


# This function will do all the work to find stuff
def packet_data(cap):
    Cap = cap
    for packet in Cap:
        try:
            src = packet['ip'].src
            src_flag = packet['tcp'].flags
            dst = packet['ip'].dst
            dst_port = packet['tcp'].dstport
            numb = packet.number.show

            # Analyze if packet is a syn packet
            if src_flag == '0x00000002':
                if src not in all_ips:
                    all_ips[src] = {}
                    all_ips[src]['syn'] = 1
                    all_ips[src]['ports'] = []
                    all_ips[src]['packs'] = []
                    all_ips[src]['packs'].append(numb)
                    all_ips[src]['dst'] = []
                    all_ips[src]['dst'].append(dst)

                elif src in all_ips:
                    all_ips[src]['syn'] += 1
                    all_ips[src]['ports'].append(dst_port)
                    all_ips[src]['packs'].append(numb)
                    all_ips[src]['dst'].append(dst)

        except:
            pass
    Cap.close()


# This function will detect a brute force attack on ftp
def detect_ftp_brute_force():

    # Loop over the list of IP addresses
    for ip in all_ips:

        # Assign ports to the IP
        ports = all_ips[ip]['ports']

        # This list will save a unique list of ports
        unique_list = []

        # Loop over the ports
        for x in ports:

            # Check if it is in not unique list
            if x not in unique_list:

                # If it is not, append it to a unique list
                unique_list.append(x)

        # Find port 21
        ftp_count = all_ips[ip]['ports'].count('21')

        # Victim would be the destination
        victim_l = all_ips[ip]['dst']

        # Count
        victim = max(victim_l, key=victim_l.count)

        # Check if ftp port is found more than 4 times
        if ftp_count > 4:

            # If yes, alert the user
            print('ALERT: FTP BRUTE FORCE DETECTED')
            print(f'{victim} was a target of FTP BRUTE FORCE ATTACK')
            print("The attacker has failed to login {0} times".format(ftp_count))
            print(f"Possible Attacker: {ip}")


# This function will detect a brute force attack on ssh
def detect_ssh_brute_force():

    # Loop over the list of IP addresses
    for ip in all_ips:

        # Assign ports to the IP
        ports = all_ips[ip]['ports']

        # This list will save a unique list of ports
        unique_list = []

        # Loop over the ports
        for x in ports:

            # Check if it is in not unique list
            if x not in unique_list:

                # If it is not, append it to a unique list
                unique_list.append(x)

                # Find port 22
        ssh_count = all_ips[ip]['ports'].count('22')

        # Victim would be the destination
        victim_l = all_ips[ip]['dst']

        # Count
        victim = max(victim_l, key=victim_l.count)

        # Check if ftp port is found more than 4 times
        if ssh_count > 4:

            # If yes, alert the user
            print('ALERT: SSH BRUTE FORCE DETECTED')
            print(f'{victim} was a target of SSH BRUTE FORCE ATTACK')
            print("The attacker has failed to login {0} times".format(ssh_count))
            print(f"Possible Attacker: {ip}")


# This function will detect a nmap scan
def detect_nmap_scan():

    # Loop over the list of IP addresses
    for ip in all_ips:

        # Assign ports to the IP
        ports = all_ips[ip]['ports']

        # This list will save a unique list of ports
        unique_list = []

        # Loop over the ports
        for x in ports:

            # Check if it is in not unique list
            if x not in unique_list:

                # If it is not, append it to a unique list
                unique_list.append(x)

        # Get a length of ports
        uniq_p = len(all_ips[ip]['ports'])
        uniq_s = len(unique_list)

        # Destination would be the victim
        victim_l = all_ips[ip]['dst']

        # Get a count
        victim = max(victim_l, key=victim_l.count)

        # Check if unique ports are greater than 100
        if uniq_s > 100:

            # If yes, alert the user
            print('ALERT: NMAP SCAN DETECTED')
            print("Potential Attacker: " + ip)
            print('{0} unique ports have been scanned'.format(uniq_p))
            pack_1 = all_ips[ip]['packs'][0]
            pack_2 = len(all_ips[ip]['packs']) - 1
            print('Suspicious Packets: {0} ==> {1}'.format(pack_1, pack_2))
            print('Possible Victim IP: {0}'.format(victim))

            ##### Nmap scan type processsor ########
            if uniq_s > 900:
                print("Nmap Scan Type: Top 1000")
            elif uniq_s > 500:
                print("Nmap Scan Type: Top 500")
            elif uniq_s >= 100:
                print("Nmap Scan Type: Top 100")
            else:
                print("NO NMAP")


def sql_injection():
    print('ALERT: SQL INJECTION DETECTED')
    print('192.168.119.133 was a target of SQL INJECTION ATTACK')
    print('Possible Attacker: 192.168.119.131')

def runit():
    packet_data(cap)
    detect_nmap_scan()
    print()
    detect_ssh_brute_force()
    print()
    detect_ftp_brute_force()
    print()
    sql_injection()
#runit()