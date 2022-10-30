import sys
import json

def ipv4_to_value(ipv4_addr):
    """
    Convert a dots-and-numbers IP address to a single numeric value.

    Example:

    There is only one return value, but it is shown here in 3 bases.

    ipv4_addr: "255.255.0.0"
    return:    0xffff0000 0b11111111111111110000000000000000 4294901760

    ipv4_addr: "1.2.3.4"
    return:    0x01020304 0b00000001000000100000001100000100 16909060
    """

    # First use split to get individual nums
    ip_bytes = ipv4_addr.split('.')
    # print(ip_bytes)

    # Need to loop through nums to make ints
    decimal = 0 
    for b in range(len(ip_bytes)):
        ints = int(b)
        # Build nums by shifting hex nums ex: (0xc6 << 24) | ....
        ip_bytes[b] = int(ip_bytes[b]) << (24-(b*8))
        decimal += ip_bytes[b]
        # print(decimal)

    hexes = ''
    hex_s = ''
    
    hex_string = "0x" + hex_s
    # print(hex_string)

    # This ^ will get us built decimal and hex nums, now convert one to binary as well
    binary = bin(decimal)
    # print(binary)

    final_output = hex_string + "   " + binary + "   " + str(decimal)
    # print(final_output)

    return decimal

    pass

def value_to_ipv4(addr):
    """
    Convert a single 32-bit numeric value to a dots-and-numbers IP
    address.

    Example:

    There is only one input value, but it is shown here in 3 bases.

    addr:   0xffff0000 0b11111111111111110000000000000000 4294901760
    return: "255.255.0.0"

    addr:   0x01020304 0b00000001000000100000001100000100 16909060
    return: "1.2.3.4"
    """

    # if we receive a hex, replace leading 0x, get bytes, get ints, join
    if '0x' in str(addr):
        addr = addr.replace('0x', '')
        hex_bytes = [''.join(x) for x in zip(*[iter(addr)]*2)]
        # print(hex_bytes)
        hex_ints = [int(x, 16) for x in hex_bytes]
        # print(hex_ints)
        ip_from_hex = ".".join(str(x) for x in hex_ints)
        # print(ip_from_hex)
        return ip_from_hex

       # if we receive a bin, replace leading 0b, get bytes, get ints, join ints
    if '0b' in str(addr):
        addr = addr.replace('0b', '')
        bin_bytes = [''.join(x) for x in zip(*[iter(addr)]*8)]
        # print(bin_bytes)
        bin_ints = [int(x, 2) for x in bin_bytes]
        # print(bin_ints)
        ip_from_bin = ".".join(str(x) for x in bin_ints)
        # print(ip_from_bin)
        return ip_from_bin
    
    # if we receive a int, 
    else:
        addr = int(addr)
        ip_from_dec = ".".join(map(lambda x: str(addr >> x & 0xFF), [24,16,8,0]))
        # print(ip_from_dec)
        return ip_from_dec
    pass

def get_subnet_mask_value(slash):
    """
    Given a subnet mask in slash notation, return the value of the mask
    as a single number. The input can contain an IP address optionally,
    but that part should be discarded.

    Example:

    There is only one return value, but it is shown here in 3 bases.

    slash:  "/16"
    return: 0xffff0000 0b11111111111111110000000000000000 4294901760

    slash:  "10.20.30.40/23"
    return: 0xfffffe00 0b11111111111111111111111000000000 4294966784
    """

    # Check if it is in ipv4 format, if so get just the subnet
    if '.' in slash:
        subnet_mask = slash.split('/')
        # print(subnet_mask)
        subnet_mask = subnet_mask[1]
        # print(subnet_mask)
        # return subnet_mask

    # If not, just get the subnet number
    else:
        subnet_mask = slash.split('/')
        subnet_mask = subnet_mask[1]
        # print(subnet_mask)
        # return subnet_mask
    
    subnet_mask = int(subnet_mask)
    subnet_val = 0

    for x in range(32):
        if x < int(slash.split('/')[1]): 
            subnet_val = (subnet_val << 1) + 1
            # print(subnet_val)
        else:
            subnet_val = (subnet_val << 1)
            # print(subnet_val)

    # print(subnet_val)

    # Get Binary value from decimal version of subnet
    bin_val = bin(subnet_val)
    # print(bin_val)

    # Get Hex value from decimal version of subnet
    hex_val = hex(subnet_val)
    # print(hex_val)

    final_val = hex_val + '     ' + bin_val + '     ' + str(subnet_val)
    # print(final_val)
    return subnet_val

    pass

def ips_same_subnet(ip1, ip2, slash):
    """
    Given two dots-and-numbers IP addresses and a subnet mask in slash
    notataion, return true if the two IP addresses are on the same
    subnet.

    FOR FULL CREDIT: this must use your get_subnet_mask_value() and
    ipv4_to_value() functions. Don't do it with pure string
    manipulation.

    This needs to work with any subnet from /1 to /31

    Example:

    ip1:    "10.23.121.17"
    ip2:    "10.23.121.225"
    slash:  "/23"
    return: True
    
    ip1:    "10.23.230.22"
    ip2:    "10.24.121.225"
    slash:  "/16"
    return: False
    """

    # Get the address from ipv4
    ip1_addr = ipv4_to_value(ip1)
    ip2_addr = ipv4_to_value(ip2)
    # print(ip1_addr)
    # print(ip2_addr)

    # Get subnet too
    subnet_mask = get_subnet_mask_value(slash)
    # print(subnet_mask)

    # Make networks ints and use bitwise addr & subnet
    ip1_network = (ip1_addr & subnet_mask)
    ip2_network = (ip2_addr & subnet_mask)
    # print(ip1_network)
    # print(ip2_network)

    # Compare
    if ip1_network == ip2_network:
        # print('True')
        return True

    else: 
        # print('False')
        return False

    pass

def get_network(ip_value, netmask):
    """
    Return the network portion of an address value.

    Example:

    ip_value: 0x01020304
    netmask:  0xffffff00
    return:   0x01020300
    """

    return ip_value
    pass

def find_router_for_ip(routers, ip):
    """
    Search a dictionary of routers (keyed by router IP) to find which
    router belongs to the same subnet as the given IP.

    Return None if no routers is on the same subnet as the given IP.

    FOR FULL CREDIT: you must do this by calling your ips_same_subnet()
    function.

    Example:

    [Note there will be more data in the routers dictionary than is
    shown here--it can be ignored for this function.]

    routers: {
        "1.2.3.1": {
            "netmask": "/24"
        },
        "1.2.4.1": {
            "netmask": "/24"
        }
    }
    ip: "1.2.3.5"
    return: "1.2.3.1"


    routers: {
        "1.2.3.1": {
            "netmask": "/24"
        },
        "1.2.4.1": {
            "netmask": "/24"
        }
    }
    ip: "1.2.5.6"
    return: None
    """

    # Go through the routers and get the netmask
    for addr in routers:
        slash = routers[addr]["netmask"]

        # Check if the ips are on the same subnet based off of the slash
        # that we got previously
        if ips_same_subnet(addr, ip, slash):
            return addr
    return None    

    pass

# Uncomment this code to have it run instead of the real main.
# Be sure to comment it back out before you submit!

# def my_tests():
#     print("-------------------------------------")
#     print("This is the result of my custom tests")
#     print("-------------------------------------")

    # print(x)

    # ipv4 to value tests


    # value to ipv4 tests
    # value_to_ipv4('0xc633640a')
    # value_to_ipv4('00b0001111101010100011010110000101')
    # value_to_ipv4('3325256714')
    # get_subnet_mask_value("10.20.30.40/23")
    # get_subnet_mask_value("/23")
    # ips_same_subnet("10.23.121.17", "10.23.121.225", "/23")
    # ips_same_subnet("10.23.230.22", "10.24.121.225", "/16")


## -------------------------------------------
## Do not modify below this line
##
## But do read it so you know what it's doing!
## -------------------------------------------

def usage():
    print("usage: netfuncs.py infile.json", file=sys.stderr)

def read_routers(file_name):
    with open(file_name) as fp:
        json_data = fp.read()
        
    return json.loads(json_data)

def print_routers(routers):
    print("Routers:")

    routers_list = sorted(routers.keys())

    for router_ip in routers_list:

        # Get the netmask
        slash_mask = routers[router_ip]["netmask"]
        netmask_value = get_subnet_mask_value(slash_mask)
        netmask = value_to_ipv4(netmask_value)

        # Get the network number
        router_ip_value = ipv4_to_value(router_ip)
        network_value = get_network(router_ip_value, netmask_value)
        network_ip = value_to_ipv4(network_value)

        print(f" {router_ip:>15s}: netmask {netmask}: " \
            f"network {network_ip}")

def print_same_subnets(src_dest_pairs):
    print("IP Pairs:")

    src_dest_pairs_list = sorted(src_dest_pairs)

    for src_ip, dest_ip in src_dest_pairs_list:
        print(f" {src_ip:>15s} {dest_ip:>15s}: ", end="")

        if ips_same_subnet(src_ip, dest_ip, "/24"):
            print("same subnet")
        else:
            print("different subnets")

def print_ip_routers(routers, src_dest_pairs):
    print("Routers and corresponding IPs:")

    all_ips = sorted(set([i for pair in src_dest_pairs for i in pair]))

    router_host_map = {}

    for ip in all_ips:
        router = str(find_router_for_ip(routers, ip))
        
        if router not in router_host_map:
            router_host_map[router] = []

        router_host_map[router].append(ip)

    for router_ip in sorted(router_host_map.keys()):
        print(f" {router_ip:>15s}: {router_host_map[router_ip]}")

def main(argv):
    if "my_tests" in globals() and callable(my_tests):
        my_tests()
        return 0

    try:
        router_file_name = argv[1]
    except:
        usage()
        return 1

    json_data = read_routers(router_file_name)

    routers = json_data["routers"]
    src_dest_pairs = json_data["src-dest"]

    print_routers(routers)
    print()
    print_same_subnets(src_dest_pairs)
    print()
    print_ip_routers(routers, src_dest_pairs)

if __name__ == "__main__":
    sys.exit(main(sys.argv))
    
