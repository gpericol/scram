from lib import Scram
from lib import DH
import binascii

# registrazione
print "registrazione"
client_scram = Scram()
client_dh = DH()
client_password = "test"

server_scram = Scram()
server_dh = DH()

#CLIENT
username = "luca@interlogica.it"
client_nonce = client_scram.nonce()
client_public_key = client_dh.public_key()

client_first_message = {
    "username": username,
    "public_key": client_public_key,
    "nonce": client_nonce
}

#SERVER
server_salt = server_scram.nonce()
server_nonce = server_scram.nonce()
ic = 4096
server_public_key = server_dh.public_key()
server_shared_key = server_dh.shared_secret(client_first_message['public_key'])
server_first_message = {
    "salt": server_salt,
    "ic": ic,
    "public_key": server_public_key,
    "client_nonce": client_nonce,
    "nonce": server_nonce
}

#CLIENT
client_shared_key = client_dh.shared_secret(server_first_message['public_key'])

if client_nonce == server_first_message['client_nonce']:
    print "client nonce OK"

salted_password = client_scram.salted_password(client_password, server_first_message['salt'], server_first_message['ic'])
secret_salted_password = client_scram.bitwise_xor(salted_password, client_shared_key)

client_second_message = {
    "secret_key": binascii.hexlify(secret_salted_password)
}

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