# Initial Setup
-----
## Step 1:

### Install python & cryptography libraries
```pip install pycryptodome```
## Step 2:

### Create SSL certificates:
 
* **Generate a server private key:**

```openssl genrsa -out server.key 2048```

* **Create a server certificate signing request (CSR):**

```openssl req -new -key server.key -out server.csr```

* **Generate a self-signed server certificate:**

```openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt```

* **Generate a client private key:**

```openssl genrsa -out client.key 2048```

* **Create a client certificate signing request (CSR):**

```openssl req -new -key client.key -out client.csr```

* **Generate a self-signed client certificate:**

```openssl x509 -req -days 365 -in client.csr -signkey client.key -out client.crt```

* **Create a CA certificate:**

```openssl req -new -x509 -days 365 -key server.key -out ca.crt```

* **Sign the client certificate with the CA certificate:**

```openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey server.key -set_serial 01 -out client.crt```

## Step 3: Implement The Server
```
import socket
import ssl
import threading

def create_server_socket(host, port):
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile='server.crt', keyfile='server.key')
    context.load_verify_locations(cafile='ca.crt')
    context.verify_mode = ssl.CERT_REQUIRED

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f'Server listening on {host}:{port}')

    while True:
        client_socket, addr = server_socket.accept()
        print(f'Connection from {addr}')
        ssl_socket = context.wrap_socket(client_socket, server_side=True)
        threading.Thread(target=handle_client, args=(ssl_socket,)).start()

def handle_client(ssl_socket):
    try:
        data = ssl_socket.recv(4096)
        print(f'Received data: {data.decode()}')
        ssl_socket.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello, VPN Client!')
    except Exception as e:
        print(f'Error: {e}')
    finally:
        ssl_socket.close()

if __name__ == "__main__":
    create_server_socket('0.0.0.0', 443)
```
## Step 4: Implement The Client
```
import socket
import ssl

def create_client_socket(host, port):
    context = ssl.create_default_context()
    context.load_cert_chain(certfile='client.crt', keyfile='client.key')
    context.load_verify_locations(cafile='ca.crt')
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_socket = context.wrap_socket(client_socket, server_hostname=host)

    ssl_socket.connect((host, port))
    print(f'Connected to {host}:{port}')

    ssl_socket.sendall(b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n')
    data = ssl_socket.recv(4096)
    print(f'Received data: {data.decode()}')

    ssl_socket.close()

if __name__ == "__main__":
    create_client_socket('127.0.0.1', 443)
```
## Step 5: Testing The VPN

* **Run the Server:**

```python vpn_server.py```

* **Run the Client:**

```python vpn_client.py```

---
# Enhancements and Add-Ons
---
## Additional Encryption (pycryptodrome)
```
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

def decrypt_message(ciphertext, key):
    decoded = base64.b64decode(ciphertext)
    nonce, ciphertext = decoded[:16], decoded[16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    message = cipher.decrypt(ciphertext).decode('utf-8')
    return message

key = get_random_bytes(16)
encrypted = encrypt_message('Hello, VPN Client!', key)
print(f'Encrypted message: {encrypted}')
decrypted = decrypt_message(encrypted, key)
print(f'Decrypted message: {decrypted}')
```
## Logging
```
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def handle_client(ssl_socket):
    try:
        data = ssl_socket.recv(4096)
        logger.info(f'Received data: {data.decode()}')
        ssl_socket.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello, VPN Client!')
    except Exception as e:
        logger.error(f'Error: {e}')
    finally:
        ssl_socket.close()
```






