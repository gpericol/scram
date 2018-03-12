import binascii
import os
import hmac
import hashlib
import uuid

class Utils(object):
    """
    Helper functions for SCRAM library
    """

    @staticmethod
    def sha256(data):
        """Returns SHA256 digest"""
        return hashlib.sha256(data).digest()

    @staticmethod
    def nonce(size):
        """Returns random HEX string of a given size"""
        return binascii.hexlify(os.urandom(size))

    @staticmethod
    def key_generation(size):
        """Returns random non-ASCII characters, including null bytes, value of a given size"""
        return os.urandom(size)

    @staticmethod
    def bitwise_xor(arg1, arg2):
        """Returns bitwise XOR"""
        value = [ord(a) ^ ord(b) for a,b in zip(arg1,arg2)]
        return ''.join(chr(x) for x in value)
    
    @staticmethod
    def hmac_generation(password, key):
        """Returns keyed-hash message authentication code given a message (password) and a secret key (key)"""
        return hmac.new(password, key, digestmod=hashlib.sha256).digest()

    @staticmethod
    def pbkdf2_hmac(password, salt, ic):
        """Returns password-based key derivation function + hmac algorithm with SHA256 as hash function of hmac"""
        return hashlib.pbkdf2_hmac('sha256', password, salt, ic)

    @staticmethod
    def generate_password():
        """Returns a random uuid4 password as string value"""
        return str(uuid.uuid4())