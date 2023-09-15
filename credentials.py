import hashlib
import os

password_file_path = "Alice/password.txt"

def hash_password(password):
    # Hashing the password using SHA-1 and return the hexadecimal representation.
    return hashlib.sha1(password.encode('utf-8')).hexdigest()

def add_user(username, password):
    # Hash the password
    hashed_password = hash_password(password)
    with open(password_file_path, "a") as pwd_file:
        pwd_file.write(f"{username},{hashed_password}\n")

def main():
    print("Add a new user to the database")
    username = input("Enter the username: ")
    password = input("Enter the password: ")
    if not os.path.exists(password_file_path):
        with open(password_file_path, "w") as pwd_file:
            pass

    add_user(username, password)
    print("Added new user")


if __name__ == "__main__":
    main()