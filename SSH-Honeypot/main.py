import paramiko
import socket
import logging
import sys


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.FileHandler("ssh_honeypot.log"),
        logging.StreamHandler()
    ]
)

server_key = paramiko.RSAKey.from_private_key_file("fake_host_key")

class HoneypotServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()
    
    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        logging.info(f"[!] Login attempt: {username}:{password}")
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

def start_honeypot(host="0.0.0.0", port=22):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(100)
        logging.info(f"[+] Honeypot listening on {host}:{port}")
        
        while True:
            client, addr = sock.accept()
            logging.info(f"[+] Connection from {addr[0]}:{addr[1]}")
            
            try:
                transport = paramiko.Transport(client)
                transport.add_server_key(server_key)
                server = HoneypotServer()
                transport.start_server(server=server)
                
                channel = transport.accept(20)
                if channel is not None:
                    channel.close()
                transport.close()
            except Exception as e:
                logging.error(f"Error handling {addr}: {e}")
                try:
                    transport.close()
                except:
                    pass
    except KeyboardInterrupt:
        logging.info("[!] Shutting down...")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Server error: {e}")

if __name__ == "__main__":
    import threading
    start_honeypot()

