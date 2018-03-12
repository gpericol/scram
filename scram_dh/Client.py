from Scram import Scram 
from DH import *
from Utils import Utils
import binascii

class ClientNonceException(Exception):
    """Client Nonce Exception class"""
    pass

class Client(object):
    """Client class:
    It permits to register and authenticate to a Server

    Attributes:
    __dh: A Diffie Hellman class

    Constants:
    NONCE_SIZE: nonce size in bits
    """
    NONCE_SIZE = 32

    def __init__(self):
        self.__dh = DH()

    def _check_nonce(self, nonce):
        """It verifies the correctness of a given nonce"""
        if nonce.count('-')  != 1:
            raise ClientNonceException
        try:
            client_nonce, server_nonce = nonce.split("-")
        except ClientNonceException:
            raise ClientNonceException
        return client_nonce, server_nonce

    def registration_pairing(self, username, password):
        """Returns dictionary with username, public key and a random Client nonce"""
        self.__data = {
            "username": username,
            "password": password,
            "nonce": Utils.nonce(self.NONCE_SIZE)
        }

        return {
            "username": self.__data['username'],
            "public_key": format(self.__dh.public_key(), 'x'),
            "client_nonce": self.__data['nonce']
        }
    
    def registration_send_password(self, salt, ic, public_key, nonce):
        """Returns encrypted salted password and combined nonce, given salt, ic, Server public key and Server nonce by the Server"""
        try:
            self.__data['shared_key'] = self.__dh.shared_secret(public_key)
            client_nonce, server_nonce = self._check_nonce(nonce)
        except DHBadKeyException:
            raise DHBadKeyException
        except ClientNonceException:
            raise ClientNonceException

        if client_nonce != self.__data['nonce']:
            raise ClientNonceException   
        
        self.__data['nonce'] = client_nonce + "-" + server_nonce

        self.__data['salted_password'] = Scram.salted_password(self.__data['password'], salt, ic)
        secret_salted_password = Utils.bitwise_xor(self.__data['salted_password'], self.__data['shared_key'])

        return {
            "secret_key": secret_salted_password,
            "nonce": self.__data['nonce'],
        }
    
    def registration_keys_generation(self, secret_server_key, secret_client_key, nonce):
        """Returns Client key, server key and stored key, given encrypted "Server key" and encrypted "Slient key" and combined nonce"""
        if self.__data['nonce'] != nonce:
            raise ClientNonceException

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
        """Returns username and a random Client nonce, given Client key and Server key"""
        self.__data['nonce'] = Utils.nonce(self.NONCE_SIZE)
        self.__data['username'] = username
        self.__data['client_key'] = client_key
        self.__data['server_key'] = server_key
        self.__data['stored_key'] = Scram.stored_key_generation(self.__data['client_key'])

        return {
            "username": username,
            "client_nonce": self.__data['nonce']
        }

    def auth_client_proof_generation(self, nonce, salt, ic):
        """Returns combined nonce and Client proof, given combined nonce, salt and ic by the Server"""
        try:
            client_nonce, server_nonce = self._check_nonce(nonce)
        except ClientNonceException:
            raise ClientNonceException

        if client_nonce != self.__data['nonce']:
            raise ClientNonceException
            
        self.__data['auth_message'] = Scram.auth_message_generation(self.__data['username'], client_nonce, salt, ic, server_nonce)
        client_signature = Scram.signature_generation(self.__data['stored_key'], self.__data['auth_message'])
        self.__data['client_proof'] = Scram.client_proof_generation(self.__data['client_key'], client_signature)

        return {
            "nonce": nonce,
            "client_proof": self.__data['client_proof']
        }

    def server_auth(self, server_signature):
        """Verifies the correctness of the given Server signature"""
        client_server_signature = Scram.signature_generation(self.__data['server_key'], self.__data['auth_message'])

        if client_server_signature != server_signature:
            raise Exception("Verification failed")