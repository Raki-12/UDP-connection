import socket
import hashlib
import rsa
import os
from Crypto.Cipher import ARC4
import threading
import queue
import sys


host = '127.0.0.1'
bob_port = 3333


# Prompt for username and password
username = input("Enter username: ")
password = input("Enter password: ")

# Hash the password using SHA-1
password_hash = hashlib.sha1(password.encode()).hexdigest()

# Generate a 128-bit random string (NB)
NB = hashlib.md5(os.urandom(16)).hexdigest()

# Create a UDP socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((host, bob_port))
message = f"{username},{NB}"
alice_port = 5555
s.sendto(message.encode(), (host, alice_port))

data, addr = s.recvfrom(1024)
data = data.decode()

# Parse the received message to get Alice's public key and random string NA
parts = data.split(',')
alice_pubkey = parts[1]
NA = parts[2]

# Load public key fingerprint from the file
with open("fingerprint.txt", "r") as fingerprint_file:
    stored_fingerprint = fingerprint_file.read().strip()

# Verify the received public key with the stored fingerprint
received_pubkey = rsa.PublicKey.load_pkcs1(alice_pubkey.encode())
received_fingerprint = hashlib.sha1(received_pubkey.save_pkcs1()).hexdigest()

if received_fingerprint != stored_fingerprint:
    print("Received public key does not match the stored fingerprint. Terminating the connection.")
    s.close()
    exit()

# Generating 128-bit random secret key (K)
K = os.urandom(16).hex()

# Encrypt the password and session key (K) with Alice's public key
encrypted_data = rsa.encrypt(f"{password},{K}".encode(), received_pubkey)

# Send the encrypted password and session key to Alice
s.sendto(encrypted_data, (host, alice_port))
data, addr = s.recvfrom(1024)
data = data.decode()

def integrity_check(ssk, m):
    return hashlib.sha1(ssk.encode() + m.encode()).hexdigest()


if data == "Connection established, attempting to authenticate... success! Secure channel established":
    print("Attempting to authenticate... Connection Okay")
    # Establish the secret session key (ssk)
    ssk = hashlib.sha1(f"{K},{NB},{NA}".encode()).hexdigest()

    # Create a queue to pass messages between threads
    message_queue = queue.Queue()
    exit_flag = False 


    def send_messages():
        global exit_flag
        while True:
            message = message_queue.get()
            h = integrity_check(ssk, message)
            cipher = ARC4.new(ssk.encode())
            encrypted_data = cipher.encrypt((message + h).encode())
            s.sendto(encrypted_data, (host, alice_port))
            if message == "exit":
                print("Connection closed, exiting program")
                exit_flag = True
                break

    # Define a function to receive messages from Alice and display them
    def receive_messages():
        global exit_flag
        while True:
            if exit_flag:
                break
            encrypted_data, addr = s.recvfrom(1024)
            cipher = ARC4.new(ssk.encode())
            decrypted_data_bytes = cipher.decrypt(encrypted_data)
            try:
                decrypted_data = decrypted_data_bytes.decode('utf-8')
            except UnicodeDecodeError:
                continue
            m, received_h = decrypted_data[:-40], decrypted_data[-40:]
            h = integrity_check(ssk, m)
            if h == received_h:
                sys.stdout.write(f"\nReceived message from Alice: {m}\n")
                sys.stdout.flush()
            else:
                sys.stdout.write("\nIntegrity check failed. Message rejected.\n")
                sys.stdout.flush()
            sys.stdout.write("Enter message to send to Alice: ")
            sys.stdout.flush()


    # Start the threads
    send_thread = threading.Thread(target=send_messages)
    receive_thread = threading.Thread(target=receive_messages)

    send_thread.start()
    receive_thread.start()

    # Read user input and put it in the queue
    while True:
        message = input("Enter message to send to Alice: ")
        message_queue.put(message)
        if message == "exit":
            break

    # Wait for the threads to finish
    send_thread.join()
    receive_thread.join()

else:
    print("Attempting to authenticate... Connection Failed.")
    s.close()
    exit()
