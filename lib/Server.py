from Scram import Scram 
from DH import DH
from Utils import Utils
import binascii

# Pensare se ha senso implementare l'id di sessione con i 2 nonce
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

    def _get_session(self, username):
        return self.__sessions.get(username)

    def _set_session(self, username):
        self.__sessions['username'] = {
            "client_nonce": None,
            "server_nonce": None,
            "shared_key": None,
            "salt": None
        }
        return self.__sessions['username']

    def _save_record(self, username, record):
        self.__data['username'] = record

    # First possibility - Client-Server registration

    def registration_pairing(self, msg):
        if self._get_session(username):
            # session already exists
            raise Exception("session error")

        session = self._set_session(username)
        session['client_nonce'] = msg['client_nonce']

        # usare try catch con eccezioni
        session['shared_key'] = self.__dh.shared_secret(msg['public_key'])
        session['server_nonce'] = Utils.nonce(32)
        session['salt'] = Utils.nonce(32)

        self._save_record(msg['username'], {
            "client_nonce": session['client_nonce'],
            "server_nonce": session['server_nonce']
        })

        return {
            "salt": session['salt'],
            "ic": self.IC,
            "public_key": format(self.__dh.public_key(), 'x'),
            "client_nonce": session['client_nonce'],
            "server_nonce": session['server_nonce']
        }

    def registration_get_password(self, msg):
        session = self._get_session(msg['username'])
        
        crypted_password = Utils.unhex(msg['secret_key'])
        salted_password = Utils.bitwise_xor(crypted_password, session['shared_key'])
        
        client_key = Utils.nonce(32)
        server_key = Utils.nonce(32)

        server_client_key = Utils.hmac_generation(salted_password, Utils.unhex(client_key))
        server_server_key = Utils.hmac_generation(salted_password, Utils.unhex(server_key))
        
        stored_key = Scram.stored_key_generation(server_client_key)

        self._save_record(msg['username'], {
            "stored_key": stored_key,
            "server_key": Utils.hex(server_server_key),
            "salt": session['salt'],
            "ic": self.IC
        })

        return_value = {
            "server_key": Utils.hex(Utils.bitwise_xor(Utils.unhex(server_key), session['shared_key'])),
            "client_key": Utils.hex(Utils.bitwise_xor(Utils.unhex(client_key), session['shared_key'])),
            "client_nonce": session['client_nonce'],
            "server_nonce": session['server_nonce']
        }

        del session
        del session[msg['username']]
        
        return return_value


    def client_authentication(self, msg):

        auth_message = Scram.auth_message_generation(msg['username'], self.__data['username']['client_nonce'], self.__data['username']['salt'], self.__data['username']['ic'], self.__data['username']['server_nonce'])
        client_signature = Scram.signature_generation(self.__data['username']['stored_key'], auth_message)
        server_signature = Scram.signature_generation(self.__data['username']['server_key'], auth_message)

        verification_message = Scram.server_final_verification(Scram.stored_key_generation(Utils.bitwise_xor(Utils.unhex(msg['client_proof']), client_signature)), self.__data['username']['stored_key'])

        return {
            "message": verification_message,
            "server_signature": Utils.hex(server_signature)
        }

    # Second possibility - User generation by the Server

    def generate_user(self, username):
        password = Utils.generate_password()
        salt = Utils.nonce(32)
        salted_password = Scram.salted_password(password, salt, self.IC)
        client_key = Utils.nonce(32)
        server_key = Utils.nonce(32)
        server_client_key = Utils.hmac_generation(salted_password, Utils.unhex(client_key))
        server_server_key = Utils.hmac_generation(salted_password, Utils.unhex(server_key))
        stored_key = Scram.stored_key_generation(server_client_key)

        record = {
            "stored_key": stored_key,
            "server_key": Utils.hex(server_server_key),
            "salt": salt,
            "ic": self.IC
        }

        self._save_record(username, record)

        print self.__data

        return {
            "username": username,
            "password": password,
            "salt": salt,
            "ic": self.IC,
            "client_key": client_key,
            "server_key": server_key            
        }
