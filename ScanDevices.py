from scapy.all import *

MY_IP = get_if_addr(conf.iface)

def Scan():
    output = arping("10.0.0.0/24")
    file = open("ip_list.txt", 'w')
    txt = ""
    for i in output[0]:
        if i[1].psrc != MY_IP:
            txt += i[1].psrc + ';' + i[1].hwsrc + "\n"
    file.write(txt)
    file.close()