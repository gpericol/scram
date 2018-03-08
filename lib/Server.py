from Scram import Scram 
from DH import DH
from Utils import Utils
import binascii

class Server(object):
    TTL = 10
    IC = 4096
    __sessions = None
    __data = None
    __dh = None
    __scram = None
    __utils = None

    def __init__(self):
        self.__sessions = {}
        self.__data = {}
        self.__dh = DH()
        self.__scram = Scram()
        self.__utils = Utils()

    def _get_session(self, username):
        return self.__sessions.get(username)

    def _set_session(self, username):
        self.__sessions['username'] = {
            "nonces": {},
            "shared_key" = None
            "salt" = None
        }
        return self.__sessions['username']

    def _save_record(self, username, keys):
        self.__data['username'] = keys

    def registration_pairing(self, client_first_message):
        if self._get_session(username):
            raise Exception("Session error")

        session = self._set_session(username)
        session['nonces'] = {
            client_first_message['nonce']: int(time.time())
        }

        session['shared_key'] = self.__dh.shared_secret(client_first_message['public_key'])
        session['salt'] = self.__utils.nonce()

        return {
            "salt": session['salt'],
            "ic": self.IC,
            "public_key": self.__dh.public_key(),
            "client_nonce": client_first_message['nonce'],
            "nonce": self.__utils.nonce()
        }

    def registration_share_keys(self, msg):
        session = self._get_session(msg['username'])
        
        crypted_password = self.__utils.unhex(msg['secret_key'])
        salted_password = self.__utils.bitwise_xor(crypted_password, session['shared_key'])
        
        client_key = self.__utils.nonce()
        server_key = self.__utils.nonce()

        server_client_key = self.__utils.hmac_generation(salted_password, self.__utils.unhex(client_key))
        server_server_key = self.__utils.hmac_generation(salted_password, self.__utils.unhex(server_key))
        
        server_stored_key = self.__scram.stored_key_generation(server_client_key)

        self._save_record(msg['username'], {
            "stored_key" = server_stored_key,
            "server_key" = self.__utils.hex(server_server_key),
            "salt" = session['salt'],
            "ic" = self.IC
        })

        return {
            "server_key": self.__utils.hex(self.__utils.bitwise_xor(self.__utils.unhex(server_key), session['shared_key'])),
            "client_key": self.__utils.hex(self.__utils.bitwise_xor(self.__utils.unhex(client_key), session['shared_key']))
        }
