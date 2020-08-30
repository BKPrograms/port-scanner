# Created by: https://github.com/BKPrograms
try:
    import scapy.all as sc
    import scapy.layers.inet as scli
    import argparse
    import os
    from art import *
    import time
    from termcolor import colored
    import random
    import socket
except ImportError:
    print("\nSome libraries seem to be missing, try running pip install -r requirements.txt")


def clearTerminal():  # Function to clear terminal
    if os.name == "posix":
        os.system("clear")
    elif os.name == "nts":
        os.system("cls")


def printIntroMessage():  # Function to print intro message
    tprint("    Port \nScanner", font="sub-zero")

    time.sleep(2)

    createdBy = text2art("Created by: ", font="smallcaps3")

    profile = colored("https://github.com/BKPrograms", "green")

    print("-----------------------------------------")

    print(createdBy + profile)

    print("-----------------------------------------")

    time.sleep(3)


def takeOptions():  # Function that takes option the user put in
    parser = argparse.ArgumentParser()  # Argument parser object that handles arguments the user passes

    parser.add_argument('-i', '--ip', dest='ip', help='IP Address/Range to scan')  # Adding option to pass in target ip

    options = parser.parse_args()  # Stores everything user passed in a var

    if not options.ip:  # Checking if user entered an IP which is necessary for the scanner to work
        parser.error('Please specify a valid IP or range, use --help for more info')  # If not, then print message

    return options.ip  # Return IP user entered and use it as target IP


def showMenuAndTakeScanChoice():
    print("Select the type of scan you would like to perform:\n")
    print("1. TCP Connect Scan: This scan sends a TCP packet to the target with a SYN flag, better for detecting open ports")
    print("2. TCP Stealth Scan: This scan is similar to the Connect Scan but is more tailored towards identifying filtered ports")
    print("3. Xmas Scan: In this scan, a TCP packet is sent with PSH, FIN, and URG flags, this scan is more tailored to detecting closed ports")
    print("4. FIN Scan: Quite similar to the Xmas Scan, except the packet is sent with the F flag instead and results will be identical to Xmas")
    print("5. NULL Scan: This scan sends a TCP packet with no flags")
    print("6. TCP ACK Scan: This sends a TCP Packet with an ACK flag, tailored for identifying Filtered Ports")
    print("0. Exit Program")
    userScanChoice = input("\n>> ")
    choices = ["0", "1", "2", "3", "4", "5", "6"]
    while userScanChoice not in choices:
        print(colored("INVALID CHOICE!", "red"))
        userScanChoice = input("\n>> ")

    return userScanChoice


class PortScanner():
    def __init__(self, targIP):
        self.targIp = targIP  # Target IP to scan for open ports on
        self.ports = list(range(1, 10001)) # [21, 22, 23, 25, 53, 80, 443, 110, 135, 1433]  # List of ports to scan

    def checkIfTargetOnline(self):
        arpRequest = sc.ARP(pdst=self.targIp)  # ARP Request Packet to find our target IP
        broadcast = sc.Ether(dst="ff:ff:ff:ff:ff:ff")  # Sending to variable MAC
        arpRequestBroadcast = broadcast / arpRequest  # Creating way to broadcast ARP packet to our target IP

        # Actually Broadcasting packet to targ IP, returns two lists of answered and unanswered responses
        answeredList = sc.srp(arpRequestBroadcast, timeout=1, verbose=False)[0]
        if len(answeredList) == 0:  # If the length of the answered lists
            print(f"{colored(self.targIp, 'red')} seems to have gone offline or maybe you've entered the incorrect IP")  # Informs attacker
            exit()  # Exit Program

    def printResultsTable(self):
        osDetectPack = sc.IP(dst = self.targIp)/scli.ICMP() # Crafting packet that will be used to determine target's OS
        osResponse = sc.sr1(osDetectPack, timeout = 2, verbose=False) # Actually sending the packet
        targetOS = "" # String that will hold what the target OS is
        if osResponse == None: # Checks if the packet had a response and it's present
            targetOS = colored("Could not identify OS!", "red") # If not then inform user that the OS could not be known

        # Otherwise, if there is a response and it contains an IP layer try to identify the OS
        elif osResponse.haslayer(scli.IP):
            if osResponse[scli.IP].ttl == 64: # Unix/Linux/FreeBSD systems use a ttl length of 64
                targetOS = colored("Unix, Linux, or FreeBSD", "green") # Inform user that it could be one of the 3
            elif osResponse[scli.IP].ttl == 128: # Unix/Linux/FreeBSD systems use a ttl length of 128
                targetOS = colored("Windows", "green") # Inform user it's Windows
        print(f"Target: {colored(self.targIp, 'green')}")  # Specifies target
        print(f"Detected target Operating System: {targetOS}\n") # Prints target OS
        # Header of results Table
        print("Port:\t\t\tStatus:\t\t\tService:\n------------------------------------------------------------")

    def dynamicPrint(self, port, portStatus):
        if portStatus == "Open":
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "Could not be determined for this port"
            print(f"\r{str(port)}\t\t\t{colored('Open', 'green')}\t\t\t{service}", end="\n")
        elif portStatus == "Filtered":
            print(f"\r{str(port)}\t\t\t{colored('Filtered', 'yellow')}", end="\n")
        elif portStatus == "Open/Filtered":
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "Could not be determined for this port"
            print(f"\r{str(port)}\t\t\t{colored('Open/Filtered', 'yellow')}\t\t\t{service}", end="\n")

    def tcpConnectScan(self):
        for port in self.ports:  # Iterates through each port
            self.checkIfTargetOnline() # Checks if target is online
            # Uses a random port instead of always using same port when transmitting packets
            localSourcePort = random.randint(1, 10000)
            # Sends a singular TCP packet with the SYN Flag to the current port and stores response in variable
            tcpConnectScanResponse = sc.sr1(sc.IP(dst=self.targIp) / sc.TCP(sport=localSourcePort, dport=port, flags="S"), timeout=1,
                                           verbose=False)
            if tcpConnectScanResponse.haslayer(sc.TCP):  # If a response was received then check it's TCP flags
                flagIndicator = tcpConnectScanResponse[sc.TCP].flags  # TCP flags stored in variable
                if flagIndicator == "SA":  # If SA flag is present, aka SYN-ACK, received then it means port is opened
                    sendReset = sc.sr(sc.IP(dst=self.targIp)/sc.TCP(sport=80,dport=port,flags="AR"), timeout=1, verbose = False)
                    # Dynamically prints new line when an open port is detected, line contains port number and "Open"
                    self.dynamicPrint(port, "Open")
                elif flagIndicator == "RA":  # If RA flag is present, it means that the target is skeptical of conn.
                    continue

    def tcpStealthScan(self):
        for port in self.ports:  # Iterates through each port
            self.checkIfTargetOnline() # Checks if target is online
            # Uses a random port instead of always using same port when transmitting packets
            localSourcePort = random.randint(1,10000)
            # Sends a singular TCP packet with the SYN Flag to the current port and stores response in variable
            tcpStealthScanResponse = sc.sr1(sc.IP(dst=self.targIp) / sc.TCP(sport=localSourcePort, dport=port, flags="S"), timeout=1,
                                           verbose=False)
            if tcpStealthScanResponse.haslayer(sc.TCP):  # If a response was received then check it's TCP flags
                flagIndicator = tcpStealthScanResponse[sc.TCP].flags  # TCP flags stored in variable
                if flagIndicator == "SA":  # If SA flag is present, aka SYN-ACK, received then it means port is opened
                    sendReset = sc.sr(sc.IP(dst=self.targIp) / sc.TCP(sport=80, dport=port, flags="AR"), timeout=1,
                                      verbose=False)
                    self.dynamicPrint(port, "Open")
                elif flagIndicator == "RA":  # If RA flag is present, it means that the target is skeptical of conn.
                    continue
            elif tcpStealthScanResponse.haslayer(scli.ICMP): # If packet has an ICMP layer, it may mean port's filtered
                # If the packet contains these codes in the ICMP layer that indicate if the port is filtered
                filterList = [1, 2, 3, 9,10, 13]
                # If the packet type is type 3 AND it contains one of the above codes then it means the port is filtered
                if tcpStealthScanResponse[sc.ICMP].type == 3 and tcpStealthScanResponse[sc.ICMP].code in filterList:
                    self.dynamicPrint(port, "Filtered")
                    continue

    def xmasScan(self):
        for port in self.ports: # Iterate through all ports
            self.checkIfTargetOnline() # Checks if target is online
            localSourcePort = random.randint(1,10000) # Use random source port and not keep one port const. open
            # Sending one TCP packet to the target with the FPU flag that makes it xmas scan
            xmasScanPKT = sc.sr1(sc.IP(dst=self.targIp) / sc.TCP(sport = localSourcePort, dport=port, flags="FPU"), verbose = False ,timeout=1)
            if not xmasScanPKT: # If there isn't a response means port is open or filtered
                self.dynamicPrint(port, "Open/Filtered")
            elif xmasScanPKT.haslayer(sc.TCP): # If there is a response and it has TCP layer check what it could mean
                # If it contains a certain flag then it means it's closed and no point in informing user
                if xmasScanPKT[sc.TCP].flags == 0x14:
                    continue
                elif xmasScanPKT.haslayer(sc.ICMP): # If it contains an ICMP layer, it could mean port is filtered
                    # If it's type is 3 and it contains one of the codes in a list, then the port is filtered
                    if xmasScanPKT[sc.ICMP].type == 3 and xmasScanPKT[sc.ICMP].code in [1, 2, 3, 9, 10, 13]:
                        self.dynamicPrint(port, "Filtered")

    def finScan(self):
        for port in self.ports: # Iterate through all ports
            self.checkIfTargetOnline() # Checks if target is online
            localSourcePort = random.randint(1,10000) # Use random source port and not keep one port const. open
            # Sending one TCP packet to the target with the F flag that makes it FIN scan
            finScanPKT = sc.sr1(sc.IP(dst=self.targIp) / sc.TCP(sport = localSourcePort, dport=port, flags="F"), verbose = False ,timeout=1)
            if not finScanPKT: # If there isn't a response means port is open or filtered
                self.dynamicPrint(port, "Open/Filtered")
            elif finScanPKT.haslayer(sc.TCP): # If there is a response and it has TCP layer check what it could mean
                # If it contains a certain flag then it means it's closed and no point in informing user
                if finScanPKT[sc.TCP].flags == 0x14:
                    continue
                elif finScanPKT.haslayer(sc.ICMP): # If it contains an ICMP layer, it could mean port is filtered
                    # If it's type is 3 and it contains one of the codes in a list, then the port is filtered
                    if finScanPKT[sc.ICMP].type == 3 and finScanPKT[sc.ICMP].code in [1, 2, 3, 9, 10, 13]:
                        self.dynamicPrint(port, "Filtered")

    def nullScan(self):
        for port in self.ports: # Iterate through all ports
            self.checkIfTargetOnline() # Checks if target is online
            localSourcePort = random.randint(1,10000) # Use random source port and not keep one port const. open
            # Sending one TCP packet to the target with no flags which is what makes it a NULL scan
            finScanPKT = sc.sr1(sc.IP(dst=self.targIp) / sc.TCP(sport = localSourcePort, dport=port, flags=""), verbose = False ,timeout=1)
            if not finScanPKT: # If there isn't a response means port is open or filtered
                self.dynamicPrint(port, "Open/Filtered")
            elif finScanPKT.haslayer(sc.TCP): # If there is a response and it has TCP layer check what it could mean
                # If it contains a certain flag then it means it's closed and no point in informing user
                if finScanPKT[sc.TCP].flags == 0x14:
                    continue
                elif finScanPKT.haslayer(sc.ICMP): # If it contains an ICMP layer, it could mean port is filtered
                    # If it's type is 3 and it contains one of the codes in a list, then the port is filtered
                    if finScanPKT[sc.ICMP].type == 3 and finScanPKT[sc.ICMP].code in [1, 2, 3, 9, 10, 13]:
                        self.dynamicPrint(port, "Filtered")


    def tcpACKScan(self):
        for port in self.ports:
            self.checkIfTargetOnline()
            localSourcePort = random.randint(1,10000) # Use random source port and not keep one port const. open
            ackFlagPKT = sc.sr1(sc.IP(dst=self.targIp) / sc.TCP(dport=port,sport = localSourcePort ,flags="A"),verbose = False , timeout=1)
            if not ackFlagPKT:
                self.dynamicPrint(port, "Filtered")
            elif ackFlagPKT.haslayer(sc.TCP):
                if ackFlagPKT[sc.TCP].flags == 0x4:
                    continue
            elif ackFlagPKT.haslayer(sc.ICMP):
                if ackFlagPKT[sc.ICMP].type == 3 and  ackFlagPKT[sc.ICMP].code == 3 in [1, 2, 3, 9, 10, 13]:
                    self.dynamicPrint(port, "Filtered")


specifiedTargetIP = takeOptions()  # Takes in user's option and stores in a variable
clearTerminal()  # Clearing Terminal
printIntroMessage()  # Printing Intro Message
scanner = PortScanner(targIP=specifiedTargetIP)  # Creating Instance of Scanner Object
scanner.checkIfTargetOnline() # Scanner obj checks if target is online and present on network
scanChoice = showMenuAndTakeScanChoice() # Show menu and take the user's scan choice
if scanChoice == "0": # Checks if user wants to exit program
    print("Exiting Program....Have a nice day!") # Notify that program is closing
    exit() # Fin
else: # If they don't want to exit then execute whichever scan type they have input
    print("PLEASE DO NOT EXIT THE SCAN EARLY, WAIT UNTIL THE SCAN COMPLETION MESSAGE HAS APPEARED")
    if scanChoice == "1": # If they input 1, then execute TCP Connect scan
        print(f"\n[{colored('+', 'green')}] Initiating TCP Connect Scan on {scanner.targIp}...\n") # Notify beginning
        scanner.printResultsTable() # Print general table header
        scanner.tcpConnectScan() # Begin TCP connect Scan
    elif scanChoice == "2": # If they input 2, then they wanted to execute a stealth TCP scan
        print(f"\n[{colored('+', 'green')}] Initiating TCP Stealth Scan on {scanner.targIp}...\n") # Notify beginning
        scanner.printResultsTable() # Print general table header
        scanner.tcpStealthScan() # Begin TCP stealth Scan
    elif scanChoice == "3": # If they input 3, then they want to use the XMAS scan
        print(f"\n[{colored('+', 'green')}] Initiating Xmas Scan on {scanner.targIp}...\n") # Notify beginning
        scanner.printResultsTable() # Print general table header
        scanner.xmasScan() # Begin Xmas Scan
    elif scanChoice == "4":
        print(f"\n[{colored('+', 'green')}] Initiating FIN Scan on {scanner.targIp}...\n") # Notify beginning
        scanner.printResultsTable() # Print general table header
        scanner.finScan() # Begin FIN Scan
    elif scanChoice == "5":
        print(f"\n[{colored('+', 'green')}] Initiating NULL Scan on {scanner.targIp}...\n") # Notify beginning
        scanner.printResultsTable() # Print general table header
        scanner.nullScan() # Begin NULL Scan
    elif scanChoice == "6":
        print(f"\n[{colored('+', 'green')}] Initiating TCP ACK Scan on {scanner.targIp}...\n")  # Notify beginning
        scanner.printResultsTable()  # Print general table header
        scanner.tcpACKScan()  # Begin TCP ACK Scan

    print(f"[{colored('+', 'green')}] Scan Complete!")
