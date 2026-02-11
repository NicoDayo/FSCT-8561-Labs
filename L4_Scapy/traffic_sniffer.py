from scapy.all import sniff, IP, IPv6, TCP, UDP
import datetime

logged = {
    "total": 0, # total packets
    "protocol_count": {}, #{"TCP": 3, "UDP": 5}
    "src_ip_count": {},  #{"192.168.1.254": 1}
    "dst_ip_count": {},  #{"10.0.0.1": 8}
    "port_count": {},    #{"80": 7, "53": 6}
}
# counter to increment the logged capture values
def increment(d, key):
    d[key] = d.get(key, 0) + 1

# function to reference each packet that is captured, keeps track of IP, ports, protocol, and creates the log for each packet
def packet_ref(pkt):
    logged["total"] += 1
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")

    # defaults
    src_ip = dst_ip = "N/A"
    protocol = "unknown"
    src_port = dst_port = "N/A"

    # checking IPv4 and IPv6
    if IP in pkt:
        ip = pkt[IP]
        src_ip, dst_ip = (ip.src, ip.dst)

    elif IPv6 in pkt:
        ip = pkt[IPv6]
        src_ip, dst_ip = ip.src, ip.dst
        increment(logged["src_ip_count"], src_ip)
        increment(logged["dst_ip_count"], dst_ip)
    
    # protocol count checks for trnasport layer
    for name, layer_class in (("TCP", TCP), ("UDP", UDP)):
        if layer_class in pkt:
            protocol = name
            layer = pkt[layer_class]
            src_port, dst_port = (layer.sport, layer.dport)
            for port in (src_port, dst_port):
                increment(logged["port_count"], str(port))
            break
    

    increment(logged["protocol_count"], protocol)

    print(f"[{timestamp}] | {protocol} | src: {src_ip} : {src_port} -> dst: {dst_ip} : {dst_port} | {pkt.summary()}")


# applying filters during the capture
def filter_choice():
    filters = {
        "1": "tcp",
        "2": "tcp port 80",
        "3": "udp port 53"
    }
    print("Filtering Options:")
    print("[1] TCP only (tcp)")
    print("[2] HTTP (tcp port 80)")
    print("[3] DNS (udp port 53)")

    choice = input("> ").strip()
    filtering = filters.get(choice)

    if not filtering:
        print("Invalid")
        return None
    return filtering

def summary_results():
    print("\n===========RESULTS=============")
    print(f"Total Packets: {logged['total']}")
    print("Protocols logged: ")
    for ptcl, num in sorted(logged["protocol_count"].items(), 
        key=lambda tup: tup[1], reverse=True):
        print(f"{ptcl}: {num}")

def main():
    option = filter_choice()
    if option:
        print(f"\nIn Progress....\n")
        sniff(filter=option, count=50, prn=packet_ref, store=False)
        print("\nFinished Capture.")
        summary_results()

if __name__ == "__main__":
    main()