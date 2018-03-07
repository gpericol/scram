from Scram import Scram 
from DH import DH
import binascii

class Client(object):
    __client_key = None
    __server_key = None
    __stored_key = None
    __username = None
    __password = None
    __salted_password = None

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
    
    def registration_second_message(self):
        pass



    


    


