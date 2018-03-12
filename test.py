from lib import Client
from lib import Server
import pprint

client = Client()
server = Server()

username = "luca"
password = "zanolini"

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
print data


