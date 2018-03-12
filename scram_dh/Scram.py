import hmac
import hashlib
from Utils import Utils

class Scram(object):

    @staticmethod
    def salted_password(password, salt, ic):
        """Returns salted password with pbkdf2-hmac algorithm, given password, salt and ic"""
        return Utils.pbkdf2_hmac(password, salt, ic)

    @staticmethod
    def stored_key_generation(client_key):
        """Returns SHA256 stored key, given Client key"""
        return Utils.sha256(client_key)

    @staticmethod
    def auth_message_generation(username, client_nonce, salt, ic, server_nonce):
        """Return the concatenation of username,  Client nonce, salt, ic and Server nonce"""
        return username+client_nonce+salt+str(ic)+server_nonce

    @staticmethod
    def signature_generation(auth_message, stored_key):
        """Returns Signature, given authentication message and stored key"""
        return Utils.hmac_generation(auth_message, stored_key)

    @staticmethod
    def client_proof_generation(client_key, client_signature):
        """Returns Client proof, given Client key and Client signature"""
        return Utils.bitwise_xor(client_key, client_signature)