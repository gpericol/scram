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
    __nonce = None

    __dh = None
    __scram = None
    __utils = None

    def __init__(self, username, password):
        self.__username = username
        self.__password = password
        self.__dh = DH()
        self.__scram = Scram()
        self.__utils = Utils()

    def registration_first_message(self):
        self.__nonce = self.__utils.nonce()
        return {
            "username": self.__username,
            "public_key": format(self.__dh.public_key(), 'x'),
            "nonce": self.__nonce
        }
    
    def registration_second_message(self, server_first_message):
        # fare try catch
        self.__shared_key = self.__dh.shared_secret(server_first_message['public_key'])
        # pensalo in maniera più furba
        if self.__nonce != server_first_message['client_nonce']:
            print "ERROR"

        salted_password = self.__scram.salted_password(self.__password, server_first_message['salt'], server_first_message['ic'])
        
        secret_salted_password = self.__utils.bitwise_xor(salted_password, self.__shared_key)

        return {
            "username": self.__username,
            "secret_key": self.__utils.hex(secret_salted_password)
        }
    
    def registration_keys_generation(self, msg):
        client_key = self.__utils.bitwise_xor(self.__utils.unhex(msg['client_key']), self.__shared_key)
        server_key = self.__utils.bitwise_xor(self.__utils.unhex(msg['server_key']), self.__shared_key)

        client_client_key = self.__utils.hmac_generation(salted_password, client_key)
        client_server_key = self.__utils.hmac_generation(salted_password, server_key)
        client_stored_key = self.__utils.stored_key_generation(client_client_key)

        return {
            "server_key": self.__utils.hex(client_server_key),
            "client_key": self.__utils.hex(client_client_key),
            "stored_key": self.__utils.hex(client_stored_key)
        }

        
}



    


    


