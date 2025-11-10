import base64
import logging
import queue
from socket import socket

from secretsocks import secretsocks

log = logging.getLogger(__name__)


def create_client(main_menu, q, session_id):
    log.info("Creating SOCKS client...")
    return EmpireSocksClient(main_menu, q, session_id)


def start_client(client, port):
    log.info("Starting SOCKS server...")
    listener = secretsocks.Listener(client, host="127.0.0.1", port=port)
    listener.wait()


class EmpireSocksClient(secretsocks.Client):
    # Initialize our data channel
    def __init__(self, main_menu, q, session_id):
        secretsocks.Client.__init__(self)
        self.main_menu = main_menu
        self.q = q
        self.agent_task_service = main_menu.agenttasksv2
        self.session_id = session_id
        self.alive = True
        self.start()

    # Receive data from our data channel and push it to the receive queue
    def recv(self):
        while self.alive:
            try:
                data = self.q.get()
                self.recvbuf.put(data)
            except socket.timeout:
                continue
            except Exception:
                self.alive = False

    # Take data from the write queue and send it over our data channel
    def write(self):
        while self.alive:
            try:
                data = self.writebuf.get(timeout=10)
                if data:
                    self.agent_task_service.create_task_socks_data(
                        self.session_id,
                        base64.b64encode(data).decode("UTF-8"),
                    )
            except queue.Empty:
                continue
            except Exception:
                self.alive = False

    def shutdown(self):
        self.alive = False
