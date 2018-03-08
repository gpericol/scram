import hmac
import hashlib

class Scram(object):

    __utils = None

    def __init__(self):
        data = {}
        self.__utils = Utils()

    def salted_password(self, password, salt, ic):
        return self.__utils.pbkdf2_hmac(password, salt, ic)

    def stored_key_generation(self, client_key):
        return self.__utils.hexed_sha256(client_key)

    def auth_message_generation(self, username, client_nonce, salt, ic, server_nonce):
        return self.__utils.hex(username+client_nonce+salt+ic+server_nonce)

    def signature_generation(self, auth_message, stored_key):
        return self.__utils.hmac_generation(auth_message, stored_key)

    def client_proof_generation(self, client_key, client_signature):
        return self.__utils.hex(self.__utils.bitwise_xor(client_key, client_signature))
    
    def server_final_verification(self, client_stored_key, server_stored_key):
        if client_stored_key == server_stored_key:
            print "Authentication with client OK"
        else:
            print "Verification failed"

    def client_final_verification(self, client_server_signature, server_server_signature):
        if client_server_signature == server_server_signature:
            print "Authentication with server OK"
        else:
            print "Verification failed"
        
            

