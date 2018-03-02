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
stored_key = server_scram.stored_key_generation(server_client_key)

server_second_message = {
    "server_key": binascii.hexlify(server_scram.bitwise_xor(binascii.unhexlify(server_key), server_shared_key)),
    "client_key": binascii.hexlify(server_scram.bitwise_xor(binascii.unhexlify(client_key), server_shared_key))
}

#CLIENT
client_key2 = client_scram.bitwise_xor(binascii.unhexlify(server_second_message['client_key']), client_shared_key)
server_key2 = client_scram.bitwise_xor(binascii.unhexlify(server_second_message['server_key']), client_shared_key)

client_client_key = client_scram.hmac_generation(salted_password, binascii.unhexlify(client_key))
client_server_key = client_scram.hmac_generation(salted_password, binascii.unhexlify(server_key))

print client_client_key == server_client_key
