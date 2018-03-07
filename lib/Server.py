from Scram import Scram 
from DH import DH
import binascii

class Server(object):
    TTL: 10
    IC = 4096
    __sessions = None
    __data = None
    __dh = None
    __scram = None

    def __init__(self):
        self.__sessions = {}
        self.__data = {}
        self.__dh = DH()
        self.__scram = Scram()

    def _get_session(self, username):
        return self.__sessions.get(username)

    def _set_session(self, username):
        self.__sessions['username'] = {
            "nonces": {},
            "shared_key" = None
            "salt" = None
        }
        return self.__sessions['username']

    def registration_first_message(self, client_first_message):
        if self._get_session(username):
            raise Exception("Session error")

        session = self._set_session(username)
        session['nonces'] = {
            client_first_message['nonce']: int(time.time())
        }

        session['shared_key'] = self.__dh.shared_secret(client_first_message['public_key'])
        session['salt'] = self.__scram.nonce()

        return {
            "salt": session['salt'],
            "ic": self.IC,
            "public_key": self.__dh.public_key(),
            "client_nonce": client_first_message['nonce'],
            "nonce": self.__scram.nonce()
        }

        
        

