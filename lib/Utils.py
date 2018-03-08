import binascii
import os
import hmac
import hashlib
import uuid

class Utils(object):
    
    @staticmethod
    def hex(data):
        return binascii.hexlify(data)
    
    @staticmethod
    def unhex(data):
        return binascii.unhexlify(data)
    
    @staticmethod
    def hexed_sha256(data):
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def nonce(size):
        return Utils.hex(os.urandom(size))

    @staticmethod
    def bitwise_xor(arg1, arg2):
        value = [ord(a) ^ ord(b) for a,b in zip(arg1,arg2)]
        return ''.join(chr(x) for x in value)
    
    @staticmethod
    def hmac_generation(password, key):
        return hmac.new(password, key, digestmod=hashlib.sha256).digest()

    @staticmethod
    def pbkdf2_hmac(password, salt, ic):
        return hashlib.pbkdf2_hmac('sha256', password, salt, ic)

    @staticmethod
    def generate_password():
        return str(uuid.uuid4())