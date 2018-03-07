import re
import base64
import hashlib
import os
import hmac
import binascii


class Scram(object):
    NONCE_SIZE = 8  # 64bit

    def __init__(self):
        data = {}

    def nonce(self):
        return binascii.hexlify(os.urandom(self.NONCE_SIZE))

    def salted_password(self, password, salt, ic):
        derived_key = hashlib.pbkdf2_hmac('sha256', password, salt, ic)
        return derived_key

    def bitwise_xor(self, arg1, arg2):
        value = [ord(a) ^ ord(b) for a,b in zip(arg1,arg2)]
        return ''.join(chr(x) for x in value)

    def hmac_generation(self, salted_password, client_key):
        keyed_hash_mac = hmac.new(salted_password, client_key, digestmod=hashlib.sha256)
        return keyed_hash_mac.digest()

    def stored_key_generation(self, client_key):
        return hashlib.sha256(client_key).hexdigest()

    def auth_message_generation(self, username, client_nonce, salt, ic, server_nonce):
        return binascii.hexlify(username+client_nonce+salt+ic+server_nonce)

    def signature_generation(self, stored_key, auth_message):
        keyed_hash_mac = hmac.new(stored_key, digestmod=hashlib.sha256)
        keyed_hash_mac.update(auth_message)
        return keyed_hash_mac.digest()

    def client_proof_generation(self, client_key, client_signature):
        return binascii.hexlify(self.bitwise_xor(client_key, client_signature))
    
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
        
            

