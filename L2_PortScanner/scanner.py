import nmap
import ipaddress

nMap = nmap.PortScanner()
target_host="127.0.0.1"
ports="20-65535"
#invalid ip test 256.256.256.256

try:
    ipaddress.ip_address(target_host)
except ValueError:
    print(f"ERROR: IP address used is invalid: {target_host}")
    raise SystemExit(0)

try: #running the scan once to see if any errors occur or nmap doesn't work
    nMap.scan(target_host, ports, timeout=400)
except nmap.PortScannerError as error:
    print(f"ERROR: {error}")
    raise SystemExit(0)

#scan information and command
print(f"{nMap.command_line()}")
print(f"scan information: {nMap.scaninfo()}\n")

all_hosts = nMap.all_hosts()
if not all_hosts: #if any hosts are not reachable then throws an error
    print(f"ERROR: No host found: {target_host} unreachable or scan has failed")
    raise SystemExit(0)

for host in all_hosts:

    print("======================")
    print(f"hosts: {nMap[host].hostname()}")
    print(f"status: {nMap[host].state()}")
    for ptcl in nMap[host].all_protocols():
        print(f"Protocol: {ptcl}")
        print("======================")
        port_list = list(nMap[host][ptcl])
        port_list.sort() # get ports for the protocol, list them and sort

        for port in port_list:
            content = nMap[host][ptcl][port]
            state = content.get("state", "unknown")
            service = content.get("name", "")
            if service:
                print(f"port: {port} : {state} | {service}")
            else:
                print(f"port: {port} : {state}")