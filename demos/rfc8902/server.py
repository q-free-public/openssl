import socket
import struct

SEC_ENT_MSG_TYPE_FAILURE=3
SEC_ENT_MSG_TYPE_GET_CERT=8
SEC_ENT_MSG_TYPE_TLS_VERIFY_CERTS=18
SEC_ENT_MSG_TYPE_TLS_SIGN_DATA=19
SEC_ENT_MSG_TYPE_TLS_VERIFY_DATA=20
SEC_ENT_MSG_TYPE_GET_AT=22

CERT_AT_EXAMPLE = (
"80030080dccf58e2fa38903130812465323364376235352d663732332d34"
"6564342d393032342d62386464386636326333303000000000001fa73c66"
"8600030001018002026f81030201c080808342582c437bf5124ad205e9b7"
"4567a66d3858079450d6d54fc63e7180a63ad61e808030edc10e97884c55"
"e993d210df77d0ea6f96171b43964e0b4fbaa08fe2fcaa6f3dcc33459940"
"bd185ad1ec3e86cfebc466400ff1c8075c6c83ecb24d05ac2c2f")

CERT_VERIFY_DATA_EXAMPLE="03810020807ba4ee969152b459048c1f4eaf2530f2fe97c5684b647577cd596b485cba54d4c002026f00023325fecacd6c020520010181010180030080dccf58e2fa38903130812465323364376235352d663732332d346564342d393032342d62386464386636326333303000000000001fa73c668600030001018002026f81030201c080808342582c437bf5124ad205e9b74567a66d3858079450d6d54fc63e7180a63ad61e808030edc10e97884c55e993d210df77d0ea6f96171b43964e0b4fbaa08fe2fcaa6f3dcc33459940bd185ad1ec3e86cfebc466400ff1c8075c6c83ecb24d05ac2c2f8080af4f996cee4e691d4f35c939473720cbc1a581f3fe7dcd0718f053e09933650eb9357f41d616c0cd9a31a219f5952f4b67b012d0302e0f82f95f94ceab9aabd0"

HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 3999  # Port to listen on (non-privileged ports are > 1023)

class MessageFactory:

	def parse_Message(self, conn):
		hdr = conn.recv(5)
		hdr_parsed = struct.unpack('>BL', hdr)
		print(hdr_parsed)
		type = hdr_parsed[0]
		print(f'Message received, type is {type}')
		msg_len = hdr_parsed[1]
		data = conn.recv(msg_len)
		if type == SEC_ENT_MSG_TYPE_GET_AT:
			return Message_get_AT(data)
		elif type == SEC_ENT_MSG_TYPE_GET_CERT:
			return Message_get_Cert(data)
		elif type == SEC_ENT_MSG_TYPE_TLS_VERIFY_CERTS:
			return Message_TLS_verify_certs(data)
		elif type == SEC_ENT_MSG_TYPE_TLS_SIGN_DATA:
			return Message_TLS_sign_data(data)
		elif type == SEC_ENT_MSG_TYPE_TLS_VERIFY_DATA:
			return Message_TLS_verify_data(data)
		else:
			return Message(type, data)

class Message:
	type = None
	msg_len = None
	data = []

	def __init__(self, type, data):
		self.type = type
		self.msg_len = len(data)
		self.data = data

	def print(self):
		print(f'Message: {self.type} {self.msg_len} {self.data}')

	def get_data(self):
		return self.data
	
	def response_message(self):
		data = self.response_data()
		resp_len = len(data)
		return struct.pack(f'>BL{resp_len}s', self.type, resp_len, data)

	def response_data(self):
		print("Generic response_data")
		return self.data
	
class Message_get_AT(Message):

	def __init__(self, data):
		super().__init__(SEC_ENT_MSG_TYPE_GET_AT, data)

	def print(self):
		print("Message: get_AT")

	def response_data(self):
		return bytes.fromhex("c43b88b23581dd3b")

class Message_get_Cert(Message):

	hash = None

	def __init__(self, data):
		super().__init__(SEC_ENT_MSG_TYPE_GET_CERT, data)
		self.hash = data

	def print(self):
		print(f'Message: get_cert {self.hash}')

	def response_data(self):
		return bytes.fromhex(CERT_AT_EXAMPLE + "00")

class Message_TLS_verify_certs(Message):

	certificates = None

	def __init__(self, data):
		super().__init__(SEC_ENT_MSG_TYPE_TLS_VERIFY_CERTS, data)
		self.certificates = data

	def print(self):
		print(f'Message: TLS_verify_certs {self.certificates}')

	def response_data(self):
		return bytes.fromhex("c43b88b23581dd3b")

class Message_TLS_sign_data(Message):

	psid = None
	hash = None
	sign_input = None

	def __init__(self, data):
		super().__init__(SEC_ENT_MSG_TYPE_TLS_SIGN_DATA, data)
		sign_len = self.msg_len - 16
		unpacked = struct.unpack(f'>Q8s{sign_len}s', data)
		self.psid = unpacked[0]
		self.hash = unpacked[1]
		self.sign_input = unpacked[2]

	def print(self):
		print(f'Message: TLS_sign_data {self.psid} {self.hash} {self.sign_input}')

	def response_data(self):
		return bytes.fromhex(CERT_VERIFY_DATA_EXAMPLE)
	
class Message_TLS_verify_data(Message):

	hash = None
	data_input = None # this is both data_signed and sign_input

	def __init__(self, data):
		super().__init__(SEC_ENT_MSG_TYPE_TLS_VERIFY_DATA, data)
		data_input_len = self.msg_len - 8
		unpacked = struct.unpack(f'>8s{data_input_len}s', data)
		self.hash = unpacked[0]
		self.data_input = unpacked[1]

	def print(self):
		print(f'Message: TLS_verify_data {self.hash} {self.data_input}')

	def response_data(self):
		psid = 623
		ssp = b'\x01\xc0'
		return struct.pack(">Q2s", psid, ssp)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind((HOST, PORT))
	s.listen()
	while True:
		conn = None
		try:
			factory = MessageFactory()
			conn, addr = s.accept()
			with conn:
				print(f"Connected by {addr}")
				msg = factory.parse_Message(conn)
				msg.print()
				if not msg:
					break
				print(f'Response = {msg.response_message()}')
				conn.sendall(msg.response_message())
				print("Response sent")
				conn.close()

		except KeyboardInterrupt:
			if conn:
				print("Closing socket")
				conn.close()
			break
