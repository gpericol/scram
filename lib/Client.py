from Scram import Scram 
from DH import *
from Utils import Utils
import binascii

class Client(object):
    __dh = None

    def __init__(self):
        self.__dh = DH()

    def _check_nonce(self, nonce):
        if nonce.count('-')  != 1:
            raise Exception("Wrong nonce")
        try:
            client_nonce, server_nonce = nonce.split("-")
        except:
            raise Exception("Wrong nonce")
        return client_nonce, server_nonce

    def registration_pairing(self, username, password):
        self.__data = {
            "username": username,
            "password": password,
            "nonce": Utils.nonce(32)
        }

        return {
            "username": self.__data['username'],
            "public_key": format(self.__dh.public_key(), 'x'),
            "client_nonce": self.__data['nonce']
        }
    
    def registration_send_password(self, salt, ic, public_key, nonce):
        try:
            self.__data['shared_key'] = self.__dh.shared_secret(public_key)
            client_nonce, server_nonce = self._check_nonce(nonce)
        except DHBadKeyException:
            raise Exception("Bad DH pairing")
        except Exception as e:
            raise Exception(str(e))

        if client_nonce != self.__data['nonce']:
            raise Exception("Bad nonce")     
        
        self.__data['nonce'] = client_nonce + "-" + server_nonce

        self.__data['salted_password'] = Scram.salted_password(self.__data['password'], salt, ic)
        secret_salted_password = Utils.bitwise_xor(self.__data['salted_password'], self.__data['shared_key'])

        return {
            "secret_key": secret_salted_password,
            "nonce": self.__data['nonce'],
        }
    
    def registration_keys_generation(self, secret_server_key, secret_client_key, nonce):
        if self.__data['nonce'] != nonce:
            raise Exception("Bad nonce") 

        client_key = Utils.bitwise_xor(secret_client_key, self.__data['shared_key'])
        server_key = Utils.bitwise_xor(secret_server_key, self.__data['shared_key'])

        client_client_key = Utils.hmac_generation(self.__data['salted_password'], client_key)
        client_server_key = Utils.hmac_generation(self.__data['salted_password'], server_key)
        client_stored_key = Scram.stored_key_generation(client_client_key)

        return_value = {
            "server_key": client_server_key,
            "client_key": client_client_key,
            "stored_key": client_stored_key
        }

        self.__data = {}

        self.__data={
            "server_key": client_server_key,
            "client_key": client_client_key,
            "stored_key": client_stored_key
        }
    
        return return_value

    def auth_pairing(self, username, client_key, server_key):
        self.__data['nonce'] = Utils.nonce(32)
        self.__data['username'] = username
        self.__data['client_key'] = client_key
        self.__data['server_key'] = server_key
        self.__data['stored_key'] = Scram.stored_key_generation(self.__data['client_key'])

        return {
            "username": username,
            "client_nonce": self.__data['nonce']
        }

    def auth_client_proof_generation(self, nonce, salt, ic):
        try:
            client_nonce, server_nonce = self._check_nonce(nonce)
        except Exception as e:
            raise Exception(str(e))

        if client_nonce != self.__data['nonce']:
            raise Exception("Bad nonce")
            
        self.__data['auth_message'] = Scram.auth_message_generation(self.__data['username'], client_nonce, salt, ic, server_nonce)
        client_signature = Scram.signature_generation(self.__data['stored_key'], self.__data['auth_message'])
        self.__data['client_proof'] = Scram.client_proof_generation(self.__data['client_key'], client_signature)

        return {
            "nonce": nonce,
            "client_proof": self.__data['client_proof']
        }

    def server_auth(self, server_signature):
        client_server_signature = Scram.signature_generation(self.__data['server_key'], self.__data['auth_message'])

        if client_server_signature != server_signature:
            raise Exception("Verification failed")