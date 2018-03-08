import binascii
import os
import hmac
import hashlib

class Utils(object):
    
    def __init__(self):
        data = {}

    def hex(self, data):
        return binascii.hexlify(data)
    
    def unhex(self, data):
        return binascii.unhexlify(data)
    
    def hexed_sha256(self, data):
        return hashlib.sha256(data).hexdigest()

    def nonce(self, size):
        return self.hex(os.urandom(size))

    def bitwise_xor(self, arg1, arg2):
        value = [ord(a) ^ ord(b) for a,b in zip(arg1,arg2)]
        return ''.join(chr(x) for x in value)
    
    def hmac_generation(self, password, key):
        return hmac.new(password, key, digestmod=hashlib.sha256).digest()

    def pbkdf2_hmac(self, password, salt, ic):
        return hashlib.pbkdf2_hmac('sha256', password, salt, ic)

