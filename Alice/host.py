import socket
import rsa
import os
import hashlib
from Crypto.Cipher import ARC4
import threading
import queue
import sys

# Define the IP address and port number
host = '127.0.0.1'
port = 5555

# Prompt for username 
username_a = input("Enter username: ")
def connection_reload():
    stop_threads_flag = threading.Event()
    with open("publickey.pem", "rb") as pub_key_file:
        pubkey = rsa.PublicKey.load_pkcs1(pub_key_file.read())
    with open("privatekey.pem", "rb") as priv_key_file:
        privkey = rsa.PrivateKey.load_pkcs1(priv_key_file.read())
    # Define a function to compute the integrity check value
    def integrity_check(ssk, m):
        return hashlib.sha1(ssk.encode() + m.encode()).hexdigest()

    # Load the password file with username, hashed_password pairs
    passwords = {}
    with open("password.txt", "r") as pwd_file:
        for line in pwd_file.readlines():
            username, pwd_hash = line.strip().split(',')
            passwords[username] = pwd_hash

    while True:
        if 's' in locals() and isinstance(s, socket.socket):
            s.close()
        print("Waiting for connection...")
        
        # Create a UDP socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((host, port))

        # Continuously listen for new connections
        while True:
            data, addr = s.recvfrom(1024)
            data = data.decode()
            if data == "exit":
                print(f"Connection closed by {username}.")
                s.close()
                continue

            # Parse the received message to get the username and random string NB
            parts = data.split(',')
            username = parts[0]
            NB = parts[1]

            # Generate a 128-bit random string (NA) for the second message in the authentication protocol
            NA = os.urandom(16).hex()

            # Send the second message in the authentication protocol to Bob
            response = f"{username_a},{pubkey.save_pkcs1().decode()},{NA}"
            s.sendto(response.encode(), addr)

            # Receive the encrypted password and session key from Bob
            encrypted_data, addr = s.recvfrom(1024)
            decrypted_data = rsa.decrypt(encrypted_data, privkey).decode()

            # Parse the decrypted data to get the password and session key (K)
            received_password, K = decrypted_data.split(',')
            received_password_hash = hashlib.sha1(received_password.encode()).hexdigest()
            if username in passwords and received_password_hash == passwords[username]:
                #If Authentication successful
                response = "Connection established, attempting to authenticate... success! Secure channel established"
                s.sendto(response.encode(), addr)
                print(f"{response}")

                # Creating the secret session key (ssk)
                ssk = hashlib.sha1(f"{K},{NB},{NA}".encode()).hexdigest()

                # Creating queue to pass messages in between threads
                message_queue = queue.Queue()

                def send():
                    while not stop_threads_flag.is_set():
                        message = message_queue.get()
                        h = integrity_check(ssk, message)
                        cipher = ARC4.new(ssk.encode())
                        encrypted_data = cipher.encrypt((message + h).encode())
                        s.sendto(encrypted_data, addr)
                    # Define a function to receive messages from Bob and display them
                def receive():
                    while not stop_threads_flag.is_set():
                        encrypted_data, addr = s.recvfrom(1024)
                        cipher = ARC4.new(ssk.encode())
                        decrypted_data = cipher.decrypt(encrypted_data).decode()
                        m, received_h = decrypted_data[:-40], decrypted_data[-40:]
                        h = integrity_check(ssk, m)
                        if h == received_h:
                            if m == "exit":
                                s.sendto("exit".encode(), addr)
                                print(f"\nConnection closed by {username}.")
                                stop_threads_flag.set()
                                s.close()
                                break
                            sys.stdout.write(f"\nReceived message from {username}: {m}\n")
                            sys.stdout.flush()
                        else:
                            sys.stdout.write("\nIntegrity check failed. Message rejected.\n")
                            sys.stdout.flush()
                        sys.stdout.write(f"Enter message to send to {username}: ")
                        sys.stdout.flush()
                    connection_reload()

                send_thread = threading.Thread(target=send)
                receive_thread = threading.Thread(target=receive)

                send_thread.start()
                receive_thread.start()

                # Read user input and put it in the queue
                while True:
                    message = input(f"Enter message to send to {username}: ")
                    message_queue.put(message)

            else:
                #If Authentication failed
                response = "Connection established, attempting to authenticate... failed! Secure channel established\nWaiting for connection..."
                s.sendto(response.encode(), addr)
                print(f"{response}")
        
connection_reload()


