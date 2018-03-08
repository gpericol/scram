from Scram import Scram 
from DH import DH
from Utils import Utils
import binascii

class Client(object):
    __client_key = None
    __server_key = None
    __stored_key = None
    __username = None
    __password = None
    __shared_key = None
    __salted_password = None
    __client_nonce = None
    __server_nonce = None

    __dh = None

    def __init__(self, username, password):
        self.__username = username
        self.__password = password
        self.__dh = DH()

    def registration_pairing(self):
        self.__client_nonce = Utils.nonce(32)
        return {
            "username": self.__username,
            "public_key": format(self.__dh.public_key(), 'x'),
            "client_nonce": self.__client_nonce
        }
    
    def registration_send_password(self, msg):
        # fare try catch
        self.__shared_key = self.__dh.shared_secret(msg['public_key'])
        
        # fare raise Error
        if self.__client_nonce != msg['client_nonce']:
            print "ERROR"

        self.__server_nonce = msg['server_nonce']

        salted_password = Scram.salted_password(self.__password, msg['salt'], msg['ic'])

        secret_salted_password = Utils.bitwise_xor(salted_password, self.__shared_key)

        return {
            "username": self.__username,
            "secret_key": Utils.hex(secret_salted_password),
            "client_nonce": self.__client_nonce,
            "server_nonce": self.__server_nonce
        }
    
    def registration_keys_generation(self, msg):

        # verifica nonce

        client_key = Utils.bitwise_xor(Utils.unhex(msg['client_key']), self.__shared_key)
        server_key = Utils.bitwise_xor(Utils.unhex(msg['server_key']), self.__shared_key)

        client_client_key = Utils.hmac_generation(salted_password, client_key)
        client_server_key = Utils.hmac_generation(salted_password, server_key)
        client_stored_key = Utils.stored_key_generation(client_client_key)

        return {
            "server_key": Utils.hex(client_server_key),
            "client_key": Utils.hex(client_client_key),
            "stored_key": Utils.hex(client_stored_key)
        }