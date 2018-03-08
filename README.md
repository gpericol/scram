# Diffie Hellman - Salted Challenge Response Authentication Message

A modified version of SCRAM Authentication 

https://wiki.tools.ietf.org/html/rfc5802 

with Diffie Hellman key exchange

https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange

# Steps

## Registration

1. A Client sends its username, a random nonce and his public key to the Server
2. The Server takes track of the Client's session, storing the received credentials. Then, it sends a random nonce, a random salt, an iteration count (4096) and its public key to the Client. Now both the parties have the shared secret key. 
3. The Client generates the salted password with PBKDF2+HMAC sending it to the Server in an encrypted way ( XOR (salted_password, shared secret key) )
4. The Server decrypts the salted password, generates 2 random nonces ("Client key" and "Server key") which will be sended in an encrypted way to the Client ( XOR ("Slient key"/"Server key", shared secret key) ). These nonces will be used to generate the Client key, the Server key and the stored key by both the parties.

## Authentication
1. Both parties generate an authenticated message
2. The Client generates the Client proof and sends it with the authenticated message to the Server
3. The Server verifies the proof and sends his signature to the Client
4. The Client verifies the Server signature
5. If all the checks are successful, ok, otherwise

![ ](https://memegenerator.net/img/instances/68189102/authentication-failed-you-shall-not-pass.jpg)

# Implementation choices

## Diffie Hellman

We have decided to implement Diffie Hellman key exchange algorithm in SCRAM with the aim to avoiding the user to use other libraries for the shared secret. Our DH library makes use of the safe prime

```
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7
88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA
2583E9CA 2AD44CE8 DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6
287C5947 4E6BC05D 99B2964F A090C3A2 233BA186 515BE7ED
1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9
93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34063199
FFFFFFFF FFFFFFFF
```

 as group order (4096 bit), with 2 as generator of the group, following the indication of 

https://www.ietf.org/rfc/rfc3526.txt.

To use different safe primes, just modify the library. 

The condition

```python
if 2 <= other_key and other_key <= self.P - 2 
```

is to avoid to consider generators that generate subgroup of order 2 (i.e., 1 and p-1). They wouldn't be secure! 

The condition

```python
pow(other_key, (self.P - 1) / 2, self.P) == 1:
```

is used to prevent low-order element's weaknesses. Note that 

```python
(self.P - 1) / 2
```
is due to the definition of safe prime ( https://en.wikipedia.org/wiki/Safe_prime ).

For further information about these conditions, see

https://crypto.stackexchange.com/questions/2131/how-should-i-check-the-received-ephemeral-diffie-hellman-public-keys

![ ](https://i.imgflip.com/1vnort.jpg)


## Scram

We have added session feature so that the Server can store Clients nonces with their relative timestamps with the aim to prevent possible attacks, such as replay attack. We have simplified some notation used in SCRAM RFC, while maintaining the original mechanism and purpose.

