import socket
from diffiehellman.diffiehellman import DiffieHellman
import sql
from sql import SQL
import sqlite3
import pickle
import datetime

SERVER_IP = "86.167.235.118"
SERVER_PORT = 12345
SERVER_PUBLIC_KEY = str()
REFRESH_RATE = int()


class Transaction:
    def __init__(self, fob_id):
        self.transaction_time = datetime.datetime.now()
        self.fob_id = fob_id
        self.success = None


class Node:
    def __init__(self, node_id):
        self.node_id = node_id
        self.authorised_users = []
        self.transaction_history = []

        # Set up crypto
        self.diffie = DiffieHellman()
        self.exchange_keys()

        self.update_authorised_users()

        print("Node Established.")

    def update_authorised_users(self):
        pass

    def load_local_cache(self):
        pass

    def send_transactions(self):
        pass

    def main_loop(self):
        pass

    def exchange_keys(self):
        self.diffie.generate_public_key()
        conn = socket.socket()
        conn.connect((SERVER_IP, SERVER_PORT))
        conn.send(b"KEYX")
        key_len = str(len(str(self.diffie.public_key))).zfill(4).encode()
        conn.send(key_len)
        conn.send(str(self.diffie.public_key).encode())

        server_key_len = int(conn.recv(4))
        server_key = int(conn.recv(server_key_len))

        self.diffie.generate_shared_secret(server_key)
        conn.send(self.crypt(self.node_id.zfill(8).encode()))
        conn.close()

    def crypt(self, text):
        key = self.diffie.shared_key
        if type(text) == str:
            text = text.encode()
        if type(key) == str:
            key = key.encode()
        assert type(text) == type(key) == bytes
        output_values = []
        for i, b in enumerate(text):
            output_values.append(b ^ key[i % len(key)])
        return bytes(output_values)

n = Node("ABDC1234")