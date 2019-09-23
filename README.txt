dnspoison.py detects any outgoing dns-qeury request and send spoofed dns-answer packet to the source.
To run the program, simply type below line at the shell.
(If you are not running with specifying python in front, don't forget to give +x permission to the file)
./dnspoison.py    or   python dnspoison.py 

usage: dnspoison.py [-h] [-i INTERFACE] [-f HOSTNAME] [--expression EXPRESSION]
optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        interface name
  -f HOSTNAME, --hostnames HOSTNAME
                        Host file name
  --expression EXPRESSION
                        bpf filter to be added

dnspoison.py will print out many flags that are extracted from the query packet which are needed to spoof the packet.
If -f flag is set, and qname is not in the hostfile, it will print "NOT INT HOSTNAME FILE"
When dnspoison.py file detects any dns-query, it will print out all flags.
Example Output:
1. Qeuring For 'www.stonybrook.edu'
IP : 192.168.1.3
SOURCE IP : 192.168.1.5
SOURCE PORT : 35447
DNS SERVER IP : 192.168.1.1
DNS QUERY ID : 51817
QUERY HOSTNAME : www.stonybrook.edu.
QUERY COUNT : 1
OPCODE : 0
QTYPE : 1
QCLASS : 1
QD : www
stonybrookedu
PACKET MADE.... SEND TO SOURCE
.
Sent 1 packets.
TIME TAKEN : 15.7799720764
PACKET SENT

2. Quering For 'www.naver.com'
IP : 192.168.1.3
SOURCE IP : 192.168.1.5
SOURCE PORT : 38849
DNS SERVER IP : 192.168.1.1
DNS QUERY ID : 11278
QUERY HOSTNAME : www.naver.com.
QUERY COUNT : 1
OPCODE : 0
QTYPE : 1
QCLASS : 1
QD : wwwnavercom
PACKET MADE.... SEND TO SOURCE
.
Sent 1 packets.
TIME TAKEN : 7.9550743103
PACKET SENT

***SOMETHING ABOUT ATTACHED PACP FILE
***PCAP FILEs HAVE DNS QUERY AND ANSWER PACKET WHEN VICTIM USE 'dig' COMMAND IN TERMINAL
***no-f.pcap file has some succesful dns poisoned packet when -f flag is not set.
***yes-f.pcap file has some successful dns poisoned packet when -f flag is set.
***'host.txt' that is included in the submission is the -f flag file that is used when testing.
