#!/usr/bin/python3

from netfilterqueue import NetfilterQueue
from scapy.all import *
import os

# WHITELIST IPS HERE
ip_list = ["172.16.0.1", "172.16.0.25"]

# Set up the bridge interface
os.system("ifconfig eth0 0.0.0.0")
os.system("ifconfig eth1 0.0.0.0")
os.system("brctl addbr br0")
os.system("brctl addif br0 eth0 eth1")
os.system("ifconfig br0 up")

#Create iptable rules
eth0Rule = "iptables -A FORWARD -m physdev --physdev-in eth0 -j NFQUEUE"
eth0IPV6Rule = "ip6tables -A FORWARD -i eth0 -j DROP"
eth1Rule = "iptables -A FORWARD -i eth1 -j ACCEPT"
eth1IPV6Rule = "ip6tables -A FORWARD -i eth1 -j DROP"

print("Setting iptable rules:")
print(eth0Rule)
print(eth0IPV6Rule)
print(eth1Rule)
print(eth1IPV6Rule)

os.system(eth0Rule)
os.system(eth0IPV6Rule)
os.system(eth1Rule)
os.system(eth1IPV6Rule)

print("Enable ipv4 forward : ")
os.system("sysctl net.ipv4.ip_forward=1")

#Function checks if packet in whitelist
def callback(payload):
    data = payload.get_payload()
    pkt = IP(data)
    print(f"Packet caught with source ip : %s and dest: %s" % (str(pkt.src), str(pkt.dst)))

    if pkt.haslayer(IP) and pkt[IP].src not in ip_list:
        # IP address is not in the list
        print(f"Source IP {pkt[IP].src} is not in the list.")
        payload.drop()
    else:
        # IP address is in the list
        print(f"Source IP {pkt[IP].src} is in the list.")
        payload.accept()

def main():
    q = NetfilterQueue()
    q.bind(0, callback)
    try:
        print("Starting capture")
        q.run()
    except KeyboardInterrupt:
        print("Clearing rules")
        # Remove the forwarded rule
        os.system('iptables -D FORWARD -m physdev --physdev-in eth0 -j NFQUEUE')
        os.system('ip6tables -D FORWARD -i eth0 -j DROP')
        os.system('iptables -D FORWARD -i eth1 -j ACCEPT')
        os.system('ip6tables -D FORWARD -i eth1 -j DROP')
        
        print("Removing bridge")
        os.system('ifconfig br0 down')
        os.system('brctl delbr br0')

        print("Disable ipv4 forward : ")
        os.system("sysctl net.ipv4.ip_forward=0")
        
        q.unbind()

if __name__ == "__main__":
  main()
