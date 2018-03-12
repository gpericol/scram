from scram_dh import Client
from scram_dh import Server
from scram_dh import AbstractRecord

# AbstractRecord Implementation *MANDATORY*
class Record(AbstractRecord):
    __data = {}

    def read(self, id):
        if self.__data.has_key(id):
            return self.__data[id]
        return None 
    
    def write(self, id, data):
        self.__data[id] = data

username = "bruce.wayne"
password = "correct horse battery staple" # ~44 bits entropy, better than "Tr0ub4dor&3"

record = Record()
server = Server(record)
client = Client()

# Registration
data = client.registration_pairing(username, password)
#1
data = server.registration_pairing(data['username'], data['client_nonce'],data['public_key'])
#2
data = client.registration_send_password(data['salt'], data['ic'], data['public_key'], data['nonce'])
#3
data = server.registration_keys_generation(data['nonce'], data['secret_key'])
#4
data = client.registration_keys_generation(data['secret_server_key'], data['secret_client_key'], data['nonce'])
client_values = data

# Authentication
data = client.auth_pairing(username, client_values['client_key'], client_values['server_key'])
#1
data = server.auth_pairing(data['username'], data['client_nonce'])
#2
data = client.auth_client_proof_generation(data['nonce'], data['salt'], data['ic'])
#3
data = server.auth_proof(data['client_proof'], data['nonce'])
#4
data = client.server_auth(data['server_signature'])