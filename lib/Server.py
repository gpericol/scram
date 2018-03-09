from Scram import Scram 
from Utils import Utils
from DH import *
from Session import *
import binascii

# Pensare se ha senso implementare l'id di sessione con i 2 nonce
class Server(object):
    TTL = 10
    IC = 4096

    def __init__(self):
        self.__sessions = Session() 
        self.__data = {}
        self.__dh = DH()

    def _get_session(self, nonce):
        if nonce.count('-')  != 1:
            raise Exception("Wrong nonce")
        try:
            client_nonce, server_nonce = nonce.split("-")
            session = self.__sessions.get_session(client_nonce)
        except SessionNotExistsException:
            raise Exception("Session does not exists")
        except:
            raise Exception("Wrong nonce")

        if session['server_nonce'] != server_nonce:
            raise Exception("Wrong server nonce")

        return client_nonce, server_nonce, session

    # First possibility - Client-Server registration

    def registration_pairing(self, username, client_nonce, public_key):
        server_nonce =  Utils.nonce(32)
        nonce = client_nonce + "-" + server_nonce
        
        try:
            self.__sessions.start_session(client_nonce)
            shared_key = self.__dh.shared_secret(public_key)
        except SessionExistsException:
            raise Exception("Session already exists")
        except DHBadKeyException:
            raise Exception("Wrong public key")

        salt = Utils.nonce(32)

        self.__sessions.set_session(client_nonce,{
            'username': username,
            'server_nonce': server_nonce,
            'shared_key': shared_key,
            'salt': salt
        })

        return {
            "salt": salt,
            "ic": self.IC,
            "public_key": format(self.__dh.public_key(), 'x'),
            "nonce": nonce
        }

    def registration_keys_generation(self, nonce, secret_key):
        try:
            client_nonce,server_nonce,session = self._get_session(nonce)
        except Exception as e:
            raise Exception(str(e))
        
        salted_password = Utils.bitwise_xor(Utils.unhex(secret_key), session['shared_key'])
        
        client_key = Utils.nonce(32)
        server_key = Utils.nonce(32)

        server_client_key = Utils.hmac_generation(salted_password, Utils.unhex(client_key))
        server_server_key = Utils.hmac_generation(salted_password, Utils.unhex(server_key))
        
        stored_key = Scram.stored_key_generation(server_client_key)

        # creare db username
        self.__data[session['username']] = {
            "stored_key": stored_key,
            "server_key": Utils.hex(server_server_key),
            "salt": session['salt'],
            "ic": self.IC
        }
        
        return_value = {
            "secret_server_key": Utils.hex(Utils.bitwise_xor(Utils.unhex(server_key), session['shared_key'])),
            "secret_client_key": Utils.hex(Utils.bitwise_xor(Utils.unhex(client_key), session['shared_key'])),
            "nonce": nonce
        }

        self.__sessions.delete_session(client_nonce)
        
        return return_value

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

        return {
            "username": username,
            "password": password,
            "salt": salt,
            "ic": self.IC,
            "client_key": client_key,
            "server_key": server_key            
        }

    def authentication_pairing(self, username, client_nonce):
        try:
            self.__sessions.start_session(client_nonce)
        except SessionExistsException:
            raise Exception("Session already exists")
        
        if self.__data.has_key('username'):
            raise Exception("Wrong username")

        server_nonce =  Utils.nonce(32)
        nonce = client_nonce + "-" + server_nonce
        salt = Utils.nonce(32)

        self.__sessions.set_session(client_nonce, {
            'username': username,
            'server_nonce': server_nonce,
            'salt': salt
        })

        return {
            "salt": salt,
            "ic": self.IC,
            "nonce": nonce
        }

    def authentication_proof(self, client_proof, nonce):    
        try:
            client_nonce, server_nonce, session = self._get_session(nonce)
        except Exception as e:
            raise Exception(str(e))
        
        record = self.__data[session['username']]

        auth_message = Scram.auth_message_generation(session['username'], client_nonce, session['salt'], self.IC, server_nonce)

        client_signature = Scram.signature_generation(record['stored_key'], auth_message)
        server_signature = Scram.signature_generation(record['server_key'], auth_message)

        if Scram.stored_key_generation(Utils.bitwise_xor(Utils.unhex(client_proof), client_signature)) != record['stored_key']:
            raise Exception("Verification failed")

        return {
            "server_signature": Utils.hex(server_signature)
        }