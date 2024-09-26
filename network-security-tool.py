
import scapy.all as scapy
import socket

def scan_network(ip_range):
    """
    Scans the given IP range and returns active hosts.
    """
    print(f"Scanning the network for active hosts in range {ip_range}...")
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    devices = []
    for element in answered_list:
        devices.append({'ip': element[1].psrc, 'mac': element[1].hwsrc})

    return devices


def scan_ports(ip):
    """
    Scans the common open ports of a specific IP.
    """
    print(f"Scanning open ports on {ip}...")
    open_ports = []
    common_ports = [21, 22, 23, 25, 80, 443, 3389]  # Add more ports if needed

    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = sock.connect_ex((ip, port))  # Returns 0 if port is open
        if result == 0:
            open_ports.append(port)
        sock.close()

    return open_ports


def display_results(devices):
    """
    Display the results of the network and port scan.
    """
    print("\nNetwork Scan Results:")
    if devices:
        for device in devices:
            print(f"IP: {device['ip']}, MAC: {device['mac']}")
            open_ports = scan_ports(device['ip'])
            if open_ports:
                print(f"  Open Ports: {', '.join(map(str, open_ports))}")
            else:
                print("  No common open ports found.")
    else:
        print("No devices found on the network.")


# Main Function
if __name__ == "__main__":
    ip_range = input("Enter the IP range to scan (e.g., 192.168.1.1/24): ")
    devices = scan_network(ip_range)
    display_results(devices)

