from lib import Client
from lib import Server
import pprint

pp = pprint.PrettyPrinter(indent=4)


server = Server()

pp.pprint(server.generate_user("luca"))

"""

#SERVER
server_salted_password = server_scram.bitwise_xor(binascii.unhexlify(client_second_message['secret_key']), server_shared_key)
client_key = server_scram.nonce()
server_key = server_scram.nonce()

server_client_key = server_scram.hmac_generation(server_salted_password, binascii.unhexlify(client_key))
server_server_key = server_scram.hmac_generation(server_salted_password, binascii.unhexlify(server_key))
server_stored_key = server_scram.stored_key_generation(server_client_key)

server_second_message = {
    "server_key": binascii.hexlify(server_scram.bitwise_xor(binascii.unhexlify(server_key), server_shared_key)),
    "client_key": binascii.hexlify(server_scram.bitwise_xor(binascii.unhexlify(client_key), server_shared_key))
}

#CLIENT
client_key2 = client_scram.bitwise_xor(binascii.unhexlify(server_second_message['client_key']), client_shared_key)
server_key2 = client_scram.bitwise_xor(binascii.unhexlify(server_second_message['server_key']), client_shared_key)

client_client_key = client_scram.hmac_generation(salted_password, binascii.unhexlify(client_key))
client_server_key = client_scram.hmac_generation(salted_password, binascii.unhexlify(server_key))
client_stored_key = client_scram.stored_key_generation(client_client_key)

client_auth_message = client_scram.auth_message_generation(username, client_nonce, server_first_message['salt'], str(server_first_message['ic']), server_first_message['nonce'])
client_client_signature = client_scram.signature_generation(client_stored_key, client_auth_message)
client_proof = client_scram.client_proof_generation(client_client_key, client_client_signature)

client_final_message = {
    "auth_message": client_auth_message
    "client_proof": client_proof
}

#SERVER
server_auth_message = server_scram.auth_message_generation(client_first_message['username'], client_first_message['nonce'], server_salt, str(ic), server_nonce)
server_client_signature = server_scram.signature_generation(server_stored_key, server_auth_message)
server_server_signature = binascii.hexlify(server_scram.signature_generation(server_server_key, server_auth_message))

server_verification_message = server_scram.server_final_verification(server_scram.stored_key_generation(server_scram.bitwise_xor(binascii.unhexlify(client_final_message['client_proof']),client_client_signature)), server_stored_key)

server_final_message = {
    "message": server_verification_message,
    "server_signature": server_server_signature
}

#CLIENT
client_server_signature = binascii.hexlify(client_scram.signature_generation(client_server_key, client_auth_message))

client_verification_message = client_scram.client_final_verification(client_server_signature, server_final_message['server_signature'])
"""