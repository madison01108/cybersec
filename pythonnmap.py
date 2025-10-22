import nmap

#instance of nmap

nm = nmap.PortScanner()

#2 targets
#nmap.org ip address for us to test and use for general public 
target = "scanme.nmap.org"
options = "-sV -sC scan_results"
 
nm.scan(target, arguments = options)

for host in nm.all_hosts():
    print("Host: %s (%s)" % (host, nm[host].hostname()))
    print("State: %s" %nm[host].state())
    for protocol in nm[host].all_protocols():
        print("Protocol: %s" % protocol)
        port_info = nm[host][protocol]
        for port, state in port_info.items():
            print("Port: %s\tstate: %s" % (port, state))