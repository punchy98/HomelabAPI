import os
import urllib.parse
import requests
import socket
import dns.resolver
import paramiko
import sqlite3
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI, HTTPException, UploadFile, File
app = FastAPI()



@app.get("/", tags=["Default"])
def read_root():
    return {"Homelab API Server"}
@app.post("/get-node-ip", summary="Get IP from hostname", tags=["Docker"])
def query(hostname: str, nameservers: str = "192.168.1.175") -> str:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [nameservers]
    answers = resolver.query(hostname, "A")
    return str(answers[0])
@app.get("/docker/ps", summary="Query running Docker containers", tags=["Docker"])
async def docker_ps():
    # Set up the SSH client and connect to the remote server
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname='192.168.1.241', username='punchy', key_filename='/home/punchy/.ssh/labkey')

    # Execute the command and capture the output
    stdin, stdout, stderr = ssh.exec_command("sudo docker ps")
    output = stdout.read().decode('utf-8')

    # Close the SSH connection and return the output
    ssh.close()
    return {"status": output}
@app.post("/docker/restart", summary="Restarts a Docker container", tags=["Docker"])
async def docker_restart(container: str):
    # Set up the SSH client and connect to the remote server
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname='192.168.1.241', username='punchy', key_filename='/home/punchy/.ssh/labkey')
    # Execute the command and capture the output
    command = ("sudo docker restart ")
    stdin, stdout, stderr = ssh.exec_command(command + container)
    output = stdout.read().decode('utf-8')
    if container in output:
        status = "Restarted container -> "+ container
    else:
        status = "Container not found -> "+ container
    # Close the SSH connection and return the output
    ssh.close()
    return {"status": status}
@app.post("/keys/generate-keypair", summary="Generates an RSA SSH keypair", tags=["SSH"])
def generate_keys(user_name: str, key_desc: str):
    # Generate RSA keypair
    key = RSA.generate(2048)

    # Store the public key in variable pub_key
    pub_key = key.publickey().export_key().decode('utf-8')

    # Store the private key in variable priv_key
    priv_key = key.export_key().decode('utf-8')

    # Connect to database
    conn = sqlite3.connect('keys.db')
    c = conn.cursor()

    # Check if table exists, create it if it doesn't
    c.execute('''CREATE TABLE IF NOT EXISTS keys
                 (id INTEGER PRIMARY KEY,
                  user_name TEXT NOT NULL,
                  priv_key TEXT NOT NULL,
                  pub_key TEXT NOT NULL,
                  key_desc TEXT NOT NULL)''')

    # Get the current max key id and increment it for the new key
    c.execute('''SELECT MAX(id) FROM keys''')
    result = c.fetchone()
    if result[0]:
        key_id = result[0] + 1
    else:
        key_id = 1
    # Insert the keypair into the database
    c.execute("INSERT INTO keys (user_name, pub_key, priv_key, key_desc) VALUES (?, ?, ?, ?)", (user_name, pub_key, priv_key, key_desc))
    keyid = c.lastrowid
    conn.commit()
    conn.close()

    return {"keyid": keyid, "user_name": user_name, "pub_key": pub_key, "priv_key": priv_key, "key_desc": key_desc}


@app.get("/keys/{key_id}", summary="Queries the database based on known keyid", tags=["SSH"])
async def get_key(key_id: int):
    db = sqlite3.connect("keys.db")
    c = db.cursor()
    c.execute("SELECT * FROM keys WHERE id=?", (key_id,))
    result = c.fetchone()
    if result:
        username, pub_key, priv_key, key_desc = result[1], result[3], result[2], result[4]
        return {"user_name": username, "priv_key": priv_key, "pub_key": pub_key, "key_desc": key_desc}
    else:
        return {"message": "Key not found"}


@app.get("/keys/user/{user_name}", summary="Queries the database based on known username", tags=["SSH"])
def get_keys_by_user_name(user_name: str):
    conn = sqlite3.connect("keys.db")
    c = conn.cursor()
    c.execute("SELECT * FROM keys WHERE user_name=?", (user_name,))
    keys = c.fetchone()
    if keys is None:
        return {"error": "User not found"}
    key_id, db_user_name, priv_key, pub_key, key_desc = keys
    return {
        "key_id": key_id,
        "user_name": db_user_name,
        "pub_key": pub_key,
        "priv_key": priv_key,
        "key_desc": key_desc,
    }

@app.get("/keys/{key_id}/write-private-key", summary="Writes the private key to a file", tags=["SSH"])
def write_private_key_to_file(key_id: int, user_name: str):
    # Connect to the local keys database called keys.db
    conn = sqlite3.connect("keys.db")
    c = conn.cursor()

    # Query the database for the key with the given id and user name
    c.execute("SELECT * FROM keys WHERE id=? AND user_name=?", (key_id, user_name))
    key = c.fetchone()

    # If the key does not exist, raise an HTTPException
    if key is None:
        raise HTTPException(status_code=404, detail="Key not found")

    # Extract the private key from the key tuple
    priv_key = key[2]

    # Write the private key to a file with the naming scheme username_id_rsa
    file_name = f"{user_name}_id_rsa"
    file_path = os.path.join(os.getcwd(), file_name)
    with open(file_path, "w") as f:
        f.write(priv_key)

    return {"message": f"Private key for {user_name} with id {key_id} written to file {file_name}"}

@app.get("/keys/{key_id}/write-public-key", summary="Writes the public key to a file", tags=["SSH"])
def write_public_key_to_file(key_id: int, user_name: str):
    # Connect to the local keys database called keys.db
    conn = sqlite3.connect("keys.db")
    c = conn.cursor()

    # Query the database for the key with the given id and user name
    c.execute("SELECT * FROM keys WHERE id=? AND user_name=?", (key_id, user_name))
    key = c.fetchone()

    # If the key does not exist, raise an HTTPException
    if key is None:
        raise HTTPException(status_code=404, detail="Key not found")

    # Extract the private key from the key tuple
    pub_key = key[3]

    # Write the private key to a file with the naming scheme username_id_rsa
    file_name = f"{user_name}_id_rsa.pub"
    file_path = os.path.join(os.getcwd(), file_name)
    with open(file_path, "w") as f:
        f.write(pub_key)

    return {"message": f"Public key for {user_name} with id {key_id} written to file {file_name}"}
@app.post("/keys/create-auth-file", tags=["SSH"])
def create_auth_file(user_name: str, remote_host: str):
    # Connect to the local keys database called keys.db
    conn = sqlite3.connect("keys.db")
    c = conn.cursor()

    # Retrieve the public key from the database for the given user
    c.execute("SELECT pub_key FROM keys WHERE user_name=?", (user_name,))
    result = c.fetchone()
    if result is None:
        return {"error": "User not found"}
    pub_key = result[0]

    # Connect to remote server
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(remote_host, username='punchy', key_filename='/home/punchy/.ssh/labkey')
    # Test if username exists on remote server
    stdin, stdout, stderr = ssh.exec_command(f"getent passwd {user_name}")
    output = stdout.read().decode('utf-8')
    if not output:
        raise HTTPException(status_code=404, detail="User not found on remote server")

    # Append public key to user's authorized_keys file
    ssh.exec_command(f"echo '{pub_key}' >> $HOME/.ssh/authorized_keys")

    # Close connections
    conn.close()
    ssh.close()

    # Return success message
    return {"message": "Public key added to remote user's authorized_keys file"}
@app.post("/keys/create-temp-key", tags=["SSH"])
def generate_temp_keys(user_name: str, key_expiry: int):
    # Connect to database
    conn = sqlite3.connect('keys.db')
    c = conn.cursor()

    # Check if table exists, create it if it doesn't
    c.execute('''CREATE TABLE IF NOT EXISTS temp_access
                 (temp_access_id INTEGER PRIMARY KEY,
                  user_name TEXT NOT NULL,
                  key_expiry INT NOT NULL,
                  key_id INT NOT NULL,
                  FOREIGN KEY (key_id)
                    REFERENCES keys (key_id)
                 )''')

    # Get the current max temp_access id and increment it for the new temp_access policy
    c.execute('''SELECT MAX(temp_access_id) FROM temp_access''')
    result = c.fetchone()
    if result[0]:
        temp_access_id = result[0] + 1
    else:
        temp_access_id = 1

    # Generate keypair using the generate-keypair endpoint
    key_desc = "Temporary Key"
    gen_key_uri = "/keys/generate-keypair"
    full_url = f"http://127.0.0.1:8000{gen_key_uri}"
    key_gen_data = {"user_name": user_name, "key_desc": key_desc}
    response = requests.post(full_url, json=key_gen_data)

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail="Failed to generate keys")

    key_data = response.json()
    key_id = key_data.get("keyid")

    # Insert the temporary access policy into the database
    c.execute("INSERT INTO temp_access (user_name, key_expiry, key_id) VALUES (?, ?, ?)", 
              (user_name, key_expiry, key_id))
    conn.commit()
    conn.close()

    return {"temp_access_id": temp_access_id, "user_name": user_name, "key_id": key_id, "key_expiry": key_expiry}

@app.post("/keys/add-private-key-from-file", summary="Add a private key from a file", tags=["SSH"])
async def add_private_key_from_file(user_name: str, key_desc: str, file: UploadFile = File(...)):
    try:
        contents = await file.read()
        priv_key = contents.decode('utf-8')

        if 'BEGIN RSA PRIVATE KEY' in priv_key:
            key = RSA.import_key(priv_key)
            pub_key = key.publickey().export_key().decode('utf-8')
        elif 'BEGIN OPENSSH PRIVATE KEY' in priv_key:
            key = serialization.load_ssh_private_key(contents, password=None)
            if isinstance(key, Ed25519PrivateKey):
                pub_key = key.public_key().public_bytes(
                    encoding=serialization.Encoding.OpenSSH,
                    format=serialization.PublicFormat.OpenSSH
                ).decode('utf-8')
            else:
                raise ValueError("Unsupported key format")
        else:
            raise ValueError("Unsupported key format")
        conn = sqlite3.connect('keys.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS keys
                     (id INTEGER PRIMARY KEY,
                      user_name TEXT NOT NULL,
                      priv_key TEXT NOT NULL,
                      pub_key TEXT NOT NULL,
                      key_desc TEXT NOT NULL)''')
        c.execute('''SELECT MAX(id) FROM keys''')
        result = c.fetchone()
        if result[0]:
            key_id = result[0] + 1
        else:
            key_id = 1
        c.execute("INSERT INTO keys (user_name, pub_key, priv_key, key_desc) VALUES (?, ?, ?, ?)", (user_name, pub_key, priv_key, key_desc))
        keyid = c.lastrowid
        conn.commit()
        conn.close()
        return {"keyid": keyid, "user_name": user_name, "pub_key": pub_key, "priv_key": priv_key, "key_desc": key_desc}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


#@app.post("/keys/key-removal")
#@app.post("/keys/create-schedule")
