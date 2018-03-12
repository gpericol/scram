from lib import Client
from lib import Server
from lib import AbstractRecord

# AbstractRecord Implementation
class Record(AbstractRecord):
    __data = {}

    def read(self, id):
        if self.__data.has_key(id):
            return self.__data[id]
        return None 
    
    def write(self, id, data):
        self.__data[id] = data

username = "tony.stark"
password = "correct horse battery staple" # ~44 bits entropy, better than "Tr0ub4dor&3"

record = Record()
server = Server(record)
client = Client()

# registration
data = client.registration_pairing(username, password)
data = server.registration_pairing(data['username'], data['client_nonce'],data['public_key'])
data = client.registration_send_password(data['salt'], data['ic'], data['public_key'], data['nonce'])
data = server.registration_keys_generation(data['nonce'], data['secret_key'])
data = client.registration_keys_generation(data['secret_server_key'], data['secret_client_key'], data['nonce'])
client_values = data

# authentication
data = client.auth_pairing(username, client_values['client_key'], client_values['server_key'])
data = server.auth_pairing(data['username'], data['client_nonce'])
data = client.auth_client_proof_generation(data['nonce'], data['salt'], data['ic'])
data = server.auth_proof(data['client_proof'], data['nonce'])
data = client.server_auth(data['server_signature'])