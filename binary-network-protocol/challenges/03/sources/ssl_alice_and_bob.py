#!/usr/bin/python

import socket
from hashlib import md5
import sys, getopt
import ssl
import random
import time

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


def sendSSLMessage(ip, port, message):
    context = ssl.create_default_context()
    context.load_verify_locations('./cert.pem')
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(10)
    ssl_client = context.wrap_socket(client)
    ssl_client.connect((ip, port))

    print("[+] Send:",message)
    ssl_client.send(message)
    response = ssl_client.recv(4096)
    print("[+] Recv:",response)

    ssl_client.close();
    return response

def login(user, ip, port):
    username = user[0]
    password = user[1]
    userbytes = sendSSLMessage(ip, port, getUserMessage(username))
    response_login = sendSSLMessage(ip, port, getMessage(userbytes, password))
    print("[+] Response:", response_login)

def main(argv):
    alice = ["alice", "aliceisthebest"]
    bob = ["bob", "bobisthebest"]
    ip = '0.0.0.0'
    port = 9999
    try:
        opts, args = getopt.getopt(argv,"h:u:a:i:p:",["help", "username=","password=","ip=","port="])
        # print(opts, args)
        # if opts == []:
        #     print('./ssl_alice_and_bob -u <username> -a <password> -i <ip> -p <port>')
        #     sys.exit(2)
    except getopt.GetoptError:
        print('./ssl_alice_and_bob -u <username> -a <password> -i <ip> -p <port>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == ('-h', "--help"):
            print('./ssl_alice_and_bob -u <username> -a <password> -i <ip> -p <port>')
            sys.exit()
        elif opt in ("-u", "--username"):
            username = arg
        elif opt in ("-a", "--password"):
            password = arg
        elif opt in ("-i", "--ip"):
            ip = arg
        elif opt in ("-p", "--port"):
            port = int(arg)

    print('[+] Connection is '+ip+':'+str(port))
    print()
    try:
        for i in range(0,10000):
            if(random.randint(0,1) == 1):
                login(alice, ip, port)
                time.sleep(random.randint(1,5))
            else:
                login(bob, ip, port)
                time.sleep(random.randint(1,5))
    except KeyboardInterrupt:
        print("\n[!] KeyboardInterrupt: Closing active socket.")
        sys.exit(2)

if __name__ == "__main__":
    main(sys.argv[1:])
