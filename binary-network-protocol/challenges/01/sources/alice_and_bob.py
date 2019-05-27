#!/usr/bin/python

import time
import random
import socket
from hashlib import md5
import sys, getopt

#
# This is a duplication of tcp_client to make it easier to create a standalone linux binary
#

def getMessage(userbytes, password):
    payload = b"\x03"+userbytes+bytes(password, 'utf-8')
    length = b"\x01"+bytes([4+len(payload)+15+4])
    length_payload = b"\x02"+bytes([len(payload)])

    checksum = b"\x04"+md5(length+length_payload+payload).digest()
    footer = b"\xff\xff"

    message = length + length_payload + payload + checksum + footer
    return message

def getUserMessage(username):
    return b"\x42"+bytes(username, 'utf-8')


def sendTCPMessage(ip, port, message):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((ip, port))
    client.send(message)
    response = client.recv(4096)
    return response

#
# End
#

def login(user, ip, port):
    username = user[0]
    password = user[1]
    userbytes = sendTCPMessage(ip, port, getUserMessage(username))
    response_login = sendTCPMessage(ip, port, getMessage(userbytes, password))
    print("[+] Response:", response_login)

def main(argv):
    alice = ["alice", "aliceisthebest"]
    bob = ["bob", "bobisthebest"]
    ip = '0.0.0.0'
    port = 9999

    try:
        opts, args = getopt.getopt(argv,"hi:p:",["help","ip=","port="])
    except getopt.GetoptError:
        print('./alice_and_bob -i <ip> -p <port>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == ('-h', "--help"):
            print('./alice_and_bob -i <ip> -p <port>')
            sys.exit()
        elif opt in ("-i", "--ip"):
            ip = arg
        elif opt in ("-p", "--port"):
            port = int(arg)

    print('[+] Connection is '+ip+':'+str(port))

    for i in range(0,10000):
        if(random.randint(0,1) == 1):
            login(alice, ip, port)
            time.sleep(random.randint(1,5))
        else:
            login(bob, ip, port)
            time.sleep(random.randint(1,5))

if __name__ == "__main__":
    main(sys.argv[1:])
