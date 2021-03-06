import socket
import threading
import sys, getopt
from hashlib import md5

def getUsernameByBytes(bytes):
    if bytes == b"\x00\x01":
        return ["Bob", "I like Alice"]
    if bytes == b"\x00\x02":
        return ["Alice", "I like Bob"]
    if bytes == b"\x00\x00":
        return ["Admin", "flag{"+md5(b"SUPERSECRETADMINSECRET").hexdigest()+"}"]
    return ["", ""]

def getBytesByUsername(username):
    if username.lower() == "bob":
        return b"\x00\x01"
    if username.lower() == "alice":
        return b"\x00\x02"
    if username.lower() == "admin":
        return b"\x00\x00"
    return b"\xff\xff"

def getGreeting(username, secret):
    print("[+] Greeting:", username, secret)
    response = "Error: unauthenticated access or violation message format."
    if(username != ""):
        response = "Hello "+username+"\n"
        response += "Your secret is \""+secret+"\"\n"
    return bytes(response, "utf-8")

def parseRequest(request):
    username = ""
    secret = ""

    if request[0:1] == b"\x42":
        username = request[1:]
        print("[+] User:", username)
        userbytes = getBytesByUsername(str(username, "utf-8"))
        return userbytes
    elif request[0:1] == b"\x01":
        print("[+] Check message format (0x01).")
        if request[2:3] == b"\x02":
            print("[+] Check message format (0x02).")
            message = parseMessage(request)
            print("[+] Incomming message parsed.")
            if message != None:
                username = message[0]
                secret = message[1]
                password = message[2]
                print("[!] Verify password:", username, password, secret)
                if verifyPassword(username, password):
                    print("[!] Passwords correct.")
                    return getGreeting(username, secret)
    return getGreeting("", "")

def verifyPassword(username, password):
    if username.lower() == "bob" and password == b"bobisthebest":
        return True;
    if username.lower() == "alice" and password == b"aliceisthebest":
        return True
    if username.lower() == "admin" and password == b"admin":
        return True
    return False

def parseMessage(request):
    if request[0:1] == b"\x01":
        length = request[1]
        if len(request) == length:
            if request[2:3] == b"\x02":
                length_payload = request[3]
                if request[4:5] == b"\x03":
                    payload = request[5:5+length_payload-1]
                    tmp = getUsernameByBytes(payload[:2])
                    username = tmp[0]
                    secret = tmp[1]
                    password = payload[2:]
                    if md5(request[:6+length_payload-2]).digest() == request[5+length_payload:length-2]:
                        print("[!] User "+username+" trying to authenticate.")
                        return [username, secret, password]
    return None

def handle_client_connection(client_socket):
    request = client_socket.recv(1024)
    print("[+] Recv:", request)

    response = parseRequest(request)
    print("[+] Send:", response)

    client_socket.send(response)
    client_socket.close()

def main(argv):
    ip = '0.0.0.0'
    port = 9999
    try:
        opts, args = getopt.getopt(argv,"hi:p:",["help","ip=","port="])
        # print(opts, args)
        # if opts == []:
        #     print('./tcp_server -i <ip> -p <port>')
        #     sys.exit(2)
    except getopt.GetoptError:
        print('./tcp_server -i <ip> -p <port>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == ('-h', "--help"):
            print('./tcp_server -i <ip> -p <port>')
            sys.exit()
        elif opt in ("-i", "--ip"):
            ip = arg
        elif opt in ("-p", "--port"):
            port = int(arg)

    bind_ip = ip
    bind_port = port

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((bind_ip, bind_port))
    server.listen(5)  # max backlog of connections

    print('[+] Listening on '+bind_ip+":"+str(bind_port))

    while True:
        try:
            client_sock, address = server.accept()
            print()
            print("[+] Accepted connection from "+address[0]+":"+str(address[1]))
            client_handler = threading.Thread(
                target=handle_client_connection,
                args=(client_sock,)  # without comma you'd get a... TypeError: handle_client_connection() argument after * must be a sequence, not _socketobject
            )
            client_handler.start()
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    main(sys.argv[1:])
