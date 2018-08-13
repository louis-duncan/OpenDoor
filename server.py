import collections
import datetime
import os
import socket
import _thread
from sql import SQL
import sqlite3
from diffiehellman.diffiehellman import DiffieHellman

RECEIVING_IP = "192.168.1.118"
RECEIVING_PORT = 54321
DATABASE_LOCATION = os.path.abspath("server.db")


class Node:
    def __init__(self, node_id, node_address, node_key):
        self.node_id = node_id
        self.addr = node_address
        self.key = node_key
        self.allowed_users = self.get_users()

    def get_users(self):
        conn = sqlite3.connect(DATABASE_LOCATION)
        bliss = SQL(conn)
        member_groups = bliss.all("SELECT group_id FROM node_group_links WHERE node_id=?", (self.node_id, ))
        allowed_ids = []
        for m in member_groups:
            for u in bliss.all("SELECT user_id FROM node_group_permissions WHERE node_group_id=?", (m, )):
                allowed_ids.append(bliss.one("SELECT access_id FROM users WHERE id=?", (u, )))
        for u in bliss.all("SELECT user_id FROM node_permissions WHERE node_id=?", (self.node_id, )):
            allowed_ids.append(bliss.one("SELECT access_id FROM users WHERE id=?", (u,)))
        return allowed_ids


class Server:
    def __init__(self):
        self.clients = []
        self.close = False
        self.log = []
        self.nodes = []

    def main_loop(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((RECEIVING_IP, RECEIVING_PORT))
        server_socket.listen(5)

        while not self.close:
            conn, addr = server_socket.accept()
            _thread.start_new_thread(self.handle_connection, (conn, addr))

    def handle_connection(self, conn, addr):
        self.add_to_log((datetime.datetime.now(),
                         "Connection Commenced.",
                         addr))
        connecting_id = conn.recv(8)
        node_details =
        if valid_id:
            conn_type = conn.recv(4)
            if conn_type == b"KEYX":
                self.key_exchange(conn, addr)
            else:
                key = self.get_key(addr)
                if (key != b"") and (key != ""):
                    if crypt(conn_type, key) == b"SYNC":
                        self.sync_node(conn, addr)
                    else:
                        self.add_to_log((datetime.datetime.now(),
                                         "Connection Refused: Unrecognised Conn Type '{}'".format(conn_type[:4]),
                                         addr))
                        conn.close()
                else:
                    self.add_to_log((datetime.datetime.now(),
                                     "Connection Refused: No Key Found.",
                                     addr))
                    conn.close()

    def get_key(self, addr):
        key = ""
        for k in self.nodes:
            print("{} - {}".format(k.addr, addr))
            if k.addr == addr:
                print("True")
                key = k.key
                break
            else:
                pass
        return key

    def store_node(self, node_id, addr, key):
        to_remove = []
        for i, k in enumerate(self.nodes):
            if k.addr == addr:
                to_remove.append(i)
            elif k.node_id == node_id:
                to_remove.append(i)
            else:
                pass
        for i in to_remove:
            p = self.nodes.pop(i)
        new_node = Node(node_id, addr, key)
        self.nodes.append(new_node)
        print("ID: {} - Address: {}-{} - Key: {}".format(new_node.node_id,
                                                         new_node.addr[0],
                                                         new_node.addr[1],
                                                         new_node.key))

    def key_exchange(self, conn, addr):
        diffie = DiffieHellman()
        diffie.generate_public_key()
        public_key = diffie.public_key
        key_to_send = str(public_key).encode()
        key_len = str(len(key_to_send)).zfill(4).encode()

        client_key_len = int(conn.recv(4))
        client_key = int(conn.recv(client_key_len))
        conn.send(key_len)
        conn.send(key_to_send)

        diffie.generate_shared_secret(client_key)

        client_id = crypt(conn.recv(8), diffie.shared_key).decode()
        conn.close()

        self.store_node(client_id, addr, diffie.shared_key)

    def sync_node(self, conn, addr):
        print("Sync from {}".format(addr))

    def add_to_log(self, entry):
        self.log.append(entry)
        print(entry)


def crypt(text, key):
    if type(text) == str:
        text = text.encode()
    if type(key) == str:
        key = key.encode()
    assert type(text) == type(key) == bytes
    assert len(key) > 1
    output_values = []
    for i, b in enumerate(text):
        output_values.append(b ^ key[i % len(key)])
    return bytes(output_values)


s = Server()
s.main_loop()
