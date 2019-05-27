#!/usr/bin/python

import socket
from hashlib import md5
import sys, getopt

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

def main(argv):
    username = ''
    password = ''
    ip = '0.0.0.0'
    port = 9999
    try:
        opts, args = getopt.getopt(argv,"h:u:a:i:p:",["help", "username=","password=","ip=","port="])
        # print(opts, args)
        if opts == []:
            print('./tcp_client -u <username> -a <password> -i <ip> -p <port>')
            sys.exit(2)
    except getopt.GetoptError:
        print('./tcp_client -u <username> -a <password> -i <ip> -p <port>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == ('-h', "--help"):
            print('./tcp_client -u <username> -a <password> -i <ip> -p <port>')
            sys.exit()
        elif opt in ("-u", "--username"):
            username = arg
        elif opt in ("-a", "--password"):
            password = arg
        elif opt in ("-i", "--ip"):
            ip = arg
        elif opt in ("-p", "--port"):
            port = int(arg)
    print('[+] Username is '+username)
    print('[+] Connection is '+ip+':'+str(port))
    print()

    userbytes = sendTCPMessage(ip, port, getUserMessage(username))
    response_login = sendTCPMessage(ip, port, getMessage(userbytes, password))
    print("[+] Response:")
    print(str(response_login, "utf-8"))

if __name__ == "__main__":
    main(sys.argv[1:])
