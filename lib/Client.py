from Scram import Scram 
from DH import DH
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

    def __init__(self, username, password):
        self.__username = username
        self.__password = password
        self.__dh = DH()
        self.__scram = Scram()

    def registration_first_message(self):
        return {
            "username": self.__username,
            "public_key": format(self.__dh.public_key(), 'x'),
            "nonce": self.__scram.nonce()
        }
    
    def registration_second_message(self, server_first_message):
        # fare try catch
        self.__shared_key = self.__dh.shared_secret(server_first_message['public_key'])
        # pensalo in maniera più furba
        if self.__nonce != server_first_message['client_nonce']:
            print "ERROR"

        salted_password = self.__scram.salted_password(self.__password, server_first_message['salt'], server_first_message['ic'])
        
        secret_salted_password = self.__scram.bitwise_xor(salted_password, self.__shared_key)

        return {
            "secret_key": binascii.hexlify(secret_salted_password)
        }



    


    


