import datetime
import json 
import os
import socket
import threading
import time 


import paramiko


HOST = os.getenv("SSH_HOST", "127.0.0.1")
PORT = int(os.getenv("SSH_PORT", 2222))
LOG_FILE = "logs/ssh.jsonl"
HOST_KEY = paramiko.RSAKey(filename="honeypot/host_key")
SESSION_TIMEOUT = 60


os.makedirs("logs", exist_ok=True)
log_lock = threading.Lock()



def log_event(event):
    event["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with log_lock, open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")



class HoneypotServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip


    def get_allowed_auths(self, username):
        return "password"


    def check_auth_password(self, username, password):
        log_event({
            "type": "login_attempt",
            "protocol": "ssh",
            "src_ip": self.client_ip,
            "username": username,
            "password": password,
        })
        return paramiko.AUTH_FAILED




def handle_client(client, addr):
    ip, port = addr
    log_event({"type": "connection", "protocol": "ssh", "src_ip": ip, "src_port": port})

    transport = paramiko.Transport(client)
    transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
    transport.add_server_key(HOST_KEY)


    try:
        transport.start_server(server=HoneypotServer(ip))
        start = time.time()
        while transport.is_active() and time.time() - start < SESSION_TIMEOUT:
            time.sleep(1)
    except Exception as e: 
        log_event({"type": "error", "protocol": "ssh", "src_ip": ip, "error": str(e)})
    finally:
        transport.close()



def main ():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(100)
    print(f"SSH honeypot listening on {HOST}:{PORT}")


    while True:
        client, addr = sock.accept()
        threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()



if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nHoneypot stopped.")