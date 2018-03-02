import re
import base64
import hashlib
import os
import hmac
import binascii


class Scram(object):
    NONCE_SIZE = 8  # 64bit

    def __init__(self):
        data = {}

    def nonce(self):
        return binascii.hexlify(os.urandom(self.NONCE_SIZE))

    def salted_password(self, password, salt, ic):
        derived_key = hashlib.pbkdf2_hmac('sha256', password, salt, ic)
        return derived_key

    def bitwise_xor(self, arg1, arg2):
        value = [ord(a) ^ ord(b) for a,b in zip(arg1,arg2)]
        return ''.join(chr(x) for x in value)

    def hmac_generation(self, salted_password, client_key):
        keyed_hash_mac = hmac.new(salted_password, client_key, digestmod=hashlib.sha256)
        return keyed_hash_mac.digest()

    def stored_key_generation(self, client_key):
        return hashlib.sha256(client_key).hexdigest()





    def client_signature_generation(stored_key, client_first_message, client_final_message_without_proof, server_first_message):
        auth_message = client_first_message[3:]+','+server_first_message+','+client_final_message_without_proof
        keyed_hash_mac2 = hmac.new(stored_key, digestmod=hashlib.sha1)
        keyed_hash_mac2.update(str(auth_message).encode('utf-8'))
        client_signature = keyed_hash_mac2.digest()
        return client_signature

    def client_final_message_without_proof(storage_client):
        storage_client['client_final_message_without_proof']='c='+str(base64.standard_b64encode(str.encode(Gs2Header())))+','+'r='+storage_client['client_first_message'].rsplit('r=', 1)[1]
        return storage_client

    

    def client_final_message(client_key, client_signature, storage_client):
        storage_client=client_final_message_without_proof(storage_client)
        client_proof = base64.b64encode(Xor(client_key, client_signature))
        storage_client['client_final_message']=storage_client['client_final_message_without_proof']+','+'p='+client_proof.decode(encoding='UTF-8')
        return storage_client

    def server_signature_generation(server_key, client_first_message, client_final_message_without_proof, server_first_message):
        auth_message = client_first_message[3:]+','+server_first_message+','+client_final_message_without_proof
        keyed_hash_mac2 = hmac.new(server_key, digestmod=hashlib.sha1)
        keyed_hash_mac2.update(str(auth_message).encode('utf-8'))
        server_signature = keyed_hash_mac2.digest()
        return server_signature

    def server_final_message(stored_key, server_signature, client_proof_from_client, client_signature, storage_server):
        temp_client_key= Xor(base64.b64decode(client_proof_from_client.encode(encoding='UTF-8')), client_signature)
        sha1 = hashlib.sha1(temp_client_key)
        temp_stored_key = sha1.digest()
        if temp_stored_key == stored_key:
            storage_server['server_final_message'] = 'v='+base64.b64encode(server_signature).decode(encoding='utf-8')
            return storage_server
        else:
            storage_server['server_final_message'] = 'e='+'error' #TODO Expand errors
            return storage_server