from Scram import Scram 
from DH import DH
import binascii

class Server(object):
    TTL = 10
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
        session['salt'] = self.__scram.nonce()

        return {
            "salt": session['salt'],
            "ic": self.IC,
            "public_key": self.__dh.public_key(),
            "client_nonce": client_first_message['nonce'],
            "nonce": self.__scram.nonce()
        }

    def registration_share_keys(self, msg):
        session = self._get_session(msg['username'])
        
        crypted_password = binascii.unhexlify(msg['secret_key'])
        salted_password = server_scram.bitwise_xor(crypted_password, session['shared_key'])
        
        client_key = self.__scram.nonce()
        server_key = self.__scram.nonce()

        server_client_key = self.__scram.hmac_generation(salted_password, binascii.unhexlify(client_key))
        server_server_key = self.__scram.hmac_generation(salted_password, binascii.unhexlify(server_key))
        
        server_stored_key = server_scram.stored_key_generation(server_client_key)

        self._save_record(msg['username'], {
            "stored_key" = server_stored_key,
            "server_key" = binascii.hexlify(server_server_key),
            "salt" = session['salt'],
            "ic" = self.IC
        })

        return {
            "server_key": binascii.hexlify(self.__scram.bitwise_xor(binascii.unhexlify(server_key), session['shared_key'])),
            "client_key": binascii.hexlify(server_scram.bitwise_xor(binascii.unhexlify(client_key), session['shared_key']))
        }
