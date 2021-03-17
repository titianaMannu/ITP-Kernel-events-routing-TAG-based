import os
import struct
import sys

from pyroute2 import IPRoute, IPDB
import ipaddress
import binascii
import socket

position = 3


def pop_tag(ipv6, tag_position):
    """
    pop a tag from the ipv6 address

    :param ipv6:  @string ipv6 hexadecimal representation
    :param tag_position: @int position of the tag
    :return: @string ipv4 dot decimal representation
    """
    if tag_position < 0 or tag_position >= 7:
        print("bad position:: position parameter must be > 0 and < 7")
        sys.exit(1)
    ip = ipaddress.IPv6Address(ipv6)
    ip = ip.exploded
    ipv6_list = ip.split(':')

    ipv4_str = ipv6_list[tag_position] + ipv6_list[tag_position + 1]
    addr_long = int(ipv4_str, 16)
    ipv4 = str(socket.inet_ntoa(struct.pack(">L", addr_long)))
    return ipv4


def export_ipv6_tunnel_addresses(segment_dictionary, tag_position):
    """
    Export a list of ipv6 from a SID

    :param tag_position: @int
    :param segment_dictionary: @dictionary
    """
    my_sid = []
    attribute_list = segment_dictionary['attrs']
    for elem in attribute_list:
        if elem[0] == 'SEG6_IPTUNNEL_SRH':
            my_sid = elem[1]['segs']
            break
    if len(my_sid) > 0:
        print("***** list of sid *****")
    for elem in my_sid:
        print("ipv6: " + elem + " tag popped: " + pop_tag(elem, tag_position))


def insert_ipv6_with_tag(ipv6, prefix, pos_to_replace, interface):
    """
    Insert a tagged ipv6 address

    :param ipv6: @string
    :param prefix: @string
    :param pos_to_replace: @int
    :param interface: @string
    """
    hostname = socket.gethostname()
    local_ipv4 = socket.gethostbyname(hostname)
    print(local_ipv4)
    new_ipv6 = push_tag(ipv6, local_ipv4, pos_to_replace)
    print(new_ipv6)
    add_ipv6_new(new_ipv6.lower() + prefix, interface)


def push_tag(ipv6, ipv4, tag_position):
    """
    push a tag into the ipv6 address at the position specified

    :param ipv6: @string hexadecimal format
    :param ipv4: @string dot decimal format
    :param tag_position: @int
    :return: @string new tagged-ipv6
    """
    if tag_position < 0 or tag_position >= 7:
        print("bad position:: position parameter must be > 0 and < 7")
        sys.exit(1)
    # ipv6 address need to be normalized
    ip = ipaddress.IPv6Address(ipv6)
    ip = ip.exploded
    # getting ipv4 hexadecimal format
    s = socket.inet_aton(ipv4)
    hex_str = str(binascii.hexlify(s).upper())
    hex_str = hex_str[2:len(hex_str) - 1]
    hex_str = hex_str[:4] + ":" + hex_str[4:]
    # ipv6 tag push
    ipv6_list = ip.split(':')
    print(ipv6_list)
    res_str = ""
    i = 0
    while i < len(ipv6_list):
        if i == tag_position:
            res_str += hex_str + ":"
            i += 2
        else:
            res_str += ipv6_list[i] + ":"
            i += 1
    if res_str[len(res_str) - 1] == ':':
        res_str = res_str[:len(res_str) - 1]
    # return the new ipv6 address
    return res_str


def sniffing_func(tag_position):
    """
    Listener of Routing Kernel events

    :param tag_position: @int
    """
    event_list = ["RTM_NEWADDR", "RTM_NEWROUTE"]
    attribute_list = ['RTA_DST', 'RTA_ENCAP', 'IFA_ADDRESS']
    with IPRoute() as ipr:
        # With IPRoute objects you have to call bind() manually
        ipr.bind()
        address_list = []
        while True:
            for message in ipr.get():
                print(message)
                if message['event'] in event_list:
                    for attribute in message['attrs']:
                        if attribute[0] == 'RTA_ENCAP':
                            export_ipv6_tunnel_addresses(attribute[1], tag_position)
                            continue
                        if attribute[0] in attribute_list and attribute[1] not in address_list:
                            print("\n\n***** A new ipv6 address has being added: " + attribute[1] + "*****\n\n")
                            address_list.append(attribute[1])


def add_ipv6_new(ip, interface):
    """
    Add an ipv6 address

    :param ip: @string ipv6 address
    :param interface: @string existing interface
    """
    os.system("sudo ip -6 addr add " + ip + " dev " + interface)


def main():
    if len(sys.argv) < 2:
        print("too few arguments, usage..\n"
              ":: -a <address> <interface> to add an ipv6 address\n"
              ":: -at <address> </prefix> <position-to-fill> <interface> to add an ipv6 address with a tag\n"
              ":: -s <tag_position> to sniff kernel network events")
        sys.exit(1)
    if sys.argv[1] == "-s":
        if len(sys.argv) < 2:
            sniffing_func(position)
        else:
            sniffing_func(sys.argv[2])
        sys.exit(0)
    elif sys.argv[1] == "-a":
        if len(sys.argv) < 4:
            print("too few arguments:: usage -a <address/prefix> <interface> to add an ipv6 address or type -s to "
                  "sniff kernel network events")
            sys.exit(1)
        add_ipv6_new(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == "-at":
        if len(sys.argv) < 5:
            print("too few arguments:: usage -at <address> </prefix> <position-to-fill> <interface> to add an ipv6 "
                  "address with a tag")
            sys.exit(1)
        insert_ipv6_with_tag(sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5])
    else:
        print("bad usage:: usage -a <address> <interface> to add an ipv6 address or type -s to sniff "
              "kernel network events")


if __name__ == '__main__':
    # sniffing_func()
    # add_ipv6_new('5001:7db8:0:f101::1/64', 'eth0')
    main()
# pop_tag("3901:0db8:0000:C0A8:0013:0000:0000:0001", 3)

#  print(push_tag("2001:0db8:0000:f101::1", "192.168.0.1", 7))
#  insert_ipv6_with_tag("2001:0db8:0000:f101::1", "/64", 3, "eth0")
