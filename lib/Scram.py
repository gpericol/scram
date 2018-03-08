import hmac
import hashlib
from Utils import Utils

class Scram(object):

    @staticmethod
    def salted_password(password, salt, ic):
        return Utils.pbkdf2_hmac(password, salt, ic)

    @staticmethod
    def stored_key_generation(client_key):
        return Utils.hexed_sha256(client_key)

    @staticmethod
    def auth_message_generation(username, client_nonce, salt, ic, server_nonce):
        return Utils.hex(username+client_nonce+salt+ic+server_nonce)

    @staticmethod
    def signature_generation(auth_message, stored_key):
        return Utils.hmac_generation(auth_message, stored_key)

    @staticmethod
    def client_proof_generation(client_key, client_signature):
        return Utils.hex(Utils.bitwise_xor(client_key, client_signature))
    
    @staticmethod
    def server_final_verification(client_stored_key, server_stored_key):
        if client_stored_key == server_stored_key:
            return True
        else:
            return False
    
    @staticmethod
    def client_final_verification(client_server_signature, server_server_signature):
        if client_server_signature == server_server_signature:
            return True
        else:
            return False
        
            

