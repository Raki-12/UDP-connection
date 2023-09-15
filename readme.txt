Credentials
1. Run credentials.py first. Go to command prompt in the path where this file exist.
Use "python credentials.py" to execute command. 
Type "bob" and "12345678" for easy way to remember or
type any username and 8 digit password you want. 
Use the same username and password while executing client.py.

Key Setup

2. Then execute "python keysetup.py" in the same command prompt path.
Keys and fingerprint will be generated.

Host
3. Open Alice folder, and open command prompt in that path.
PIP install threading, pycryptodome, hashlib, rsa, socket, queue, sys.
After installing run "python host.py" and enter "Alice" as username or any username will work.
It will wait for connection.

Client
4. Now open Bob folder and open command prompt in that path.
You don't have to pip install anything now because everything will be already installed
in the previous step.
Now run "python client.py", it will ask for username and password.
Enter username and password which you entered during the execution of credentials.py.

5. After entering the right username and password, secure UDP connection will be established.
Any messages that will be sent either side will be encrypted in one side 
and decrypted in the other side.
