import sys

from pyroute2 import IPRoute, IPDB


def sniffing_func():
    event_list = ["RTM_NEWADDR", "RTM_NEWROUTE"]
    with IPRoute() as ipr:
        # With IPRoute objects you have to call bind() manually
        ipr.bind()
        while True:
            for message in ipr.get():
                print(message)
                if message['event'] in event_list:
                    print("\n\n\n***** A new ipv6 address has being added: " + message['attrs'][0]+";"+  message['attrs'][0]+ "*****\n\n\n")


def add_ipv6(address, interface):
    # commit operation is implied with the exit of the "with" statement
    with IPDB() as ipdb:
        with ipdb.interfaces[interface] as my_interface:
            my_interface.up()
            my_interface.add_ip(address)


def main():
    if len(sys.argv) < 2:
        print("too few arguments:: usage -a <address> <interface> to add an ipv6 address or type -s to sniff "
              "kernel network events")
        sys.exit(1)
    if sys.argv[1] == "-s":
        sniffing_func()
        sys.exit(0)
    elif sys.argv[1] == "-a":
        if len(sys.argv) < 4:
            print("too few arguments:: usage -a <address> <interface> to add an ipv6 address or type -s to sniff "
                  "kernel network events")
            sys.exit(1)
        add_ipv6(sys.argv[2], sys.argv[3])
    else:
        print("bad usage:: usage -a <address> <interface> to add an ipv6 address or type -s to sniff "
              "kernel network events")


if __name__ == '__main__':
    # sniffing_func()
    # add_ipv6('2001:0db8:0:f101::1/64', 'eth0')
    main()
