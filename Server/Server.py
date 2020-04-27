#!/usr/bin/env python3

########################################################################

import socket
import argparse
import sys
import time
import threading
import struct

########################################################################

# Read in the config.py file to set various addresses and ports.
from config import *

Format = 'utf-8'
tcp_port = 8000
message = b'Commands Available: getdir, makeroom, deleteroom, bye.'

########################################################################
# Broadcast Server class
########################################################################

class Client:
    HOSTNAME = '192.168.2.108'
    TIMEOUT = 2
    RECV_SIZE = 256

    TTL = 1  # Hops
    TTL_SIZE = 1  # Bytes
    TTL_BYTE = TTL.to_bytes(TTL_SIZE, byteorder='big')

    # OR: TTL_BYTE = struct.pack('B', TTL)

    thread_flag = 1

    def __init__(self):

        self.prompt_user_forever()

    def create_udp_socket(self):
        try:
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, Client.TTL_BYTE)
            # self.udp_socket.bind(Client1_Address_Port)
        except Exception as msg:
            print(msg)
            sys.exit(1)


    def create_get_socket(self,address_port):
        try:
            self.get_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.get_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)

            # Bind to an address/port. In multicast, this is viewed as
            # a "filter" that deterimines what packets make it to the
            # UDP app.
            self.get_socket.bind((RX_BIND_ADDRESS, address_port[1]))

            ############################################################
            # The multicast_request must contain a bytes object
            # consisting of 8 bytes. The first 4 bytes are the
            # multicast group address. The second 4 bytes are the
            # interface address to be used. An all zeros I/F address
            # means all network interfaces.
            ############################################################

            multicast_group_bytes = socket.inet_aton(address_port[0])

            print("Multicast Group: ", address_port[0])

            # Set up the interface to be used.
            multicast_if_bytes = socket.inet_aton(RX_IFACE_ADDRESS)

            # Form the multicast request.
            multicast_request = multicast_group_bytes + multicast_if_bytes

            # You can use struct.pack to create the request, but it is more complicated, e.g.,
            # 'struct.pack("<4sl", multicast_group_bytes,
            # int.from_bytes(multicast_if_bytes, byteorder='little'))'
            # or 'struct.pack("<4sl", multicast_group_bytes, socket.INADDR_ANY)'

            # Issue the Multicast IP Add Membership request.
            print("Adding membership (address/interface): ", address_port[0], "/", RX_IFACE_ADDRESS)
            self.get_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, multicast_request)
        except Exception as msg:
            print(msg)
            sys.exit(1)


    def create_tcp_socket(self):
        try:
            # Create an IPv4 TCP socket.
            self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except Exception as msg:
            print(msg)
            sys.exit(1)


    def connect_to_server(self):
        try:
            self.tcp_socket.connect((Client.HOSTNAME, tcp_port))
        except Exception as msg:
            print(msg)
            exit()


    def prompt_user_forever(self):

        name = "anonymous"

        while True:
            self.create_tcp_socket()
            connect_prompt_input = input("\n" + "Main Command: ")

            if connect_prompt_input == "connect":
                self.connect_to_server()
                self.tcp_socket.sendall(connect_prompt_input.encode(Format))
                data = self.tcp_socket.recv(Client.RECV_SIZE)
                print(data.decode(Format))

                getdir_flag = 0
                while True:

                    if getdir_flag:
                        connect_prompt_input = "getdir"
                        getdir_flag = 0
                    else:
                        connect_prompt_input = input("\n" + "CRD Command: ")

                    if connect_prompt_input == "getdir":
                        self.tcp_socket.sendall(connect_prompt_input.encode(Format))
                        data = self.tcp_socket.recv(Client.RECV_SIZE)
                        print("Chatrooms Available: ", data.decode(Format))

                    elif connect_prompt_input[:9] == "makeroom ":  # makeroom <chat room name> <address> <port>
                        self.tcp_socket.sendall(connect_prompt_input.encode(Format))
                        getdir_flag = 1

                    elif connect_prompt_input[:11] == "deleteroom ":
                        self.tcp_socket.sendall(connect_prompt_input.encode(Format))
                        getdir_flag = 1

                    elif connect_prompt_input[:5] == "name ":
                        name = connect_prompt_input.split()[1][1:-1]

                    elif connect_prompt_input == "bye":
                        self.tcp_socket.sendall(connect_prompt_input.encode(Format))
                        self.tcp_socket.close()
                        break

                    elif connect_prompt_input[:5] == "chat ":
                        self.chatmode(connect_prompt_input,name)
                        self.tcp_socket.sendall(b"bye")
                        break

                    else:
                        print("Invalid Command.")
                        print(message.decode(Format))

            else:
                print("Invalid Command.\n")
                print(message.decode(Format))
                continue


    def chatmode(self,connect_prompt_input, username):

        self.tcp_socket.sendall(connect_prompt_input.encode(Format))
        address_port_str = self.tcp_socket.recv(Client.RECV_SIZE).decode(Format).split(',') # ("address", "port")
        address_port = (address_port_str[0][2:-1],int(address_port_str[1][2:-2]))  # [1:] to get rid of the space

        self.create_udp_socket()

        self.create_get_socket(address_port)

        send = threading.Thread(target=self.chat_send,args=(address_port,username,))
        receive = threading.Thread(target=self.chat_receive,args=(username,))
        send.start()
        receive.start()
        send.join()
        receive.join()
        Client.thread_flag = 1



    def chat_send(self, address_port, username):

        print("You can now start to chat.\n")
        while True:

            if Client.thread_flag:
                text = input()
                if text == "quit":
                    Client.thread_flag = 0
                else:
                    msg = username + ": " + text
                    self.udp_socket.sendto(msg.encode(Format), address_port)
            else:
                print("Exiting Chat Room.")
                self.udp_socket.close()
                self.get_socket.close()
                break


    def chat_receive(self, username):

        while True:
            try:
                data, addr_port = self.get_socket.recvfrom(Client.RECV_SIZE)
                name = data.decode(Format).split(':')[0]
                msg = data.decode(Format).split(':')[1][1:]
                if name != username:
                    print(data.decode(Format))
            except:
                break





########################################################################
# Echo Server class
########################################################################

class Server:
    MAX_CONNECTION_BACKLOG = 10
    RECV_SIZE = 256
    TCP_ADDRESS = "0.0.0.0"
    list = []

    def __init__(self):

        self.create_tcp_socket()
        self.receive_forever()


    def create_tcp_socket(self):
        try:
            # Create an IPv4 TCP socket.
            self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Set socket layer socket options. This allows us to reuse
            # the socket without waiting for any timeouts.
            self.tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind socket to socket address, i.e., IP address and port.
            self.tcp_socket.bind((Server.TCP_ADDRESS,tcp_port))

            # Set socket to listen state.
            self.tcp_socket.listen(Server.MAX_CONNECTION_BACKLOG)
            print("Chat Room Direcotry Server listening on port {}...".format(tcp_port))
        except Exception as msg:
            print(msg)
            sys.exit(1)


    def receive_forever(self):

        while True:
            client = self.tcp_socket.accept()  # return a tuple (new_socket,(address,port))
            threading.Thread(target=self.connection_handler, args=(client,)).start()


    def connection_handler(self, client):
        connection, address_port = client
        connection.setblocking(True)
        threadName = "User" + threading.currentThread().getName()[-1]
        address, port = address_port

        while True:

                try:
                    cmd_bytes = connection.recv(Server.RECV_SIZE)
                    cmd = cmd_bytes.decode(Format)
                except:
                    print(threadName, " - Closing client connection ... ")
                    connection.close()

                if cmd == "connect":
                    print(threadName, " - Receiving Connection from {}".format(address_port))
                    connection.sendall(message)

                elif cmd == "getdir":
                    packet = str(Server.list).encode(Format)
                    connection.sendall(packet)

                elif cmd[:9] == "makeroom ":  # makeroom <chat room name> <address> <port>
                    room_info = cmd.split()
                    room_name = room_info[1][1:-1]
                    room_address = room_info[2][1:-1]
                    room_port = room_info[3][1:-1]
                    room  = (room_name,room_address,room_port)
                    Server.list.append(room)

                elif cmd[:11] == "deleteroom ":  # deleteroom <chat room name>
                    room_info = cmd.split()
                    room_name = room_info[1][1:-1]
                    for chatroom in Server.list:
                        if room_name in chatroom:
                            del Server.list[Server.list.index(chatroom)]
                        else:
                            print(room_name, " is not in the list.")

                elif cmd[:5] == "chat ":
                    room_addr_port = b"Room not Found."

                    room_name = cmd.split()[1][1:-1]
                    for chatroom in Server.list:
                        if room_name in chatroom:
                            room_addr_port = str((chatroom[1], chatroom[2])).encode(Format)
                            break
                    connection.sendall(room_addr_port)



                elif cmd == "bye":
                    print(threadName, "is disconnected. ")
                    connection.close()
                    break






########################################################################
# Process command line arguments if run directly.
########################################################################

if __name__ == '__main__':
    roles = {'server': Server, 'client': Client}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles,
                        help='client or server role',
                        required=True, type=str)

    args = parser.parse_args()
    roles[args.role]()

########################################################################





