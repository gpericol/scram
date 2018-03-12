# SCRAM-SHA256 ❤️ Ephemeral DH

A modified version of SCRAM-SHA256 Authentication 

https://wiki.tools.ietf.org/html/rfc5802 

https://tools.ietf.org/html/rfc7677

with Ephemeral Diffie Hellman key exchange

https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange

#### Designed and built with all the Love❤️ in the World🌍 by Luca Zanolini & Gianluca Pericoli

# How does it work

## Registration

We have decided to implement this part of the scheme in a way that the User can choose between 2 possibilities.

### First possibility - Client-Server registration

1. A Client sends its username, a random nonce and his public key to the Server
2. The Server takes track of the Client's session, storing the received credentials. Then, it sends a random nonce, a random salt, an iteration count (4096) and its public key to the Client. Now both the parties have the shared secret key. 
3. The Client generates the salted password with PBKDF2+HMAC algorithm sending it to the Server in an encrypted way ( XOR (salted_password, shared secret key) )
4. The Server decrypts the salted password, generates 2 random nonces ("Client key" and "Server key") which will be sended in an encrypted way to the Client ( XOR ("Client key"/"Server key", shared secret key) ). These nonces will be used to generate the Client key, the Server key and the stored key by both the parties.

```
CLIENT                                                                            SERVER
   |                                                                                |
#1 |        registration_pairing - (username, public_key, client_nonce)             |
   | -----------------------------------------------------------------------------> |
   |                                                                                |
#2 |            registration_pairing - (salt, ic, public_key, nonce)                |
   | <----------------------------------------------------------------------------- |
   |                                                                                |
#3 |               registration_send_password - (secret_key, nonce)                 |
   | -----------------------------------------------------------------------------> |
   |                                                                                |
#4 | registration_keys_generation - (secret_server_key, secret_client_key, nonce)   |
   | <----------------------------------------------------------------------------- |
```


### Second possibility - User generation by the Server

1. A Client sends its username and a random nonce to the Server
2. The Server takes track of the Client's session, storing the received credentials. Then, it randomly generates a uuid4 password for that Client, it generates a random nonce, a random salt, an iteration count (4096) and it creates the salted password with PBKDF2+HMAC algorithm. Lastly, the Server generates 2 random nonces ("Client key" and "Server key"). These nonces will be used to generate the Client key, the Server key and the stored key by both the parties.
3. The Client starts an ssh session with the Server and it securely takes the salted password, "Client key", "Server key", the salt, the ic and the Server nonce. 

## Authentication

This part is common for both.

1. Both parties generate an authenticated message
2. The Client generates the Client proof and sends it with the authenticated message to the Server
3. The Server verifies the proof and sends his signature to the Client
4. The Client verifies the Server signature
5. If all the checks are successful, ok, otherwise

![you shall not pass](https://memegenerator.net/img/instances/68189102/authentication-failed-you-shall-not-pass.jpg)

```
CLIENT                                                                            SERVER
   |                                                                                |
#1 |                    auth_pairing - (username, client_nonce)                     |
   | -----------------------------------------------------------------------------> |
   |                                                                                |
#2 |                         auth_pairing - (salt, ic, nonce)                       |
   | <----------------------------------------------------------------------------- |
   |                                                                                |
#3 |               auth_client_proof_generation - (client_proof, nonce)             |
   | -----------------------------------------------------------------------------> |
   |                                                                                |
#4 |                         auth_proof - (server_signature)                        |
   | <----------------------------------------------------------------------------- |
```


# How to use
Please look at `test.py` on this repo

On the Server you must implement the abstract class `lib/AbstractRecord` choosing the storing structure for the keys


# Implementation choices

## Ephemeral Diffie Hellman

We have decided to implement Ephemeral Diffie Hellman key exchange algorithm in SCRAM-SHA256 with the aim to avoiding the user to use other libraries for the shared secret. Our DH library makes use of the safe prime

```

   FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08
   8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B
   302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9
   A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6
   49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8
   FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
   670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C
   180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
   3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D
   04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D
   B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226
   1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
   BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC
   E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7 88719A10 BDBA5B26
   99C32718 6AF4E23C 1A946834 B6150BDA 2583E9CA 2AD44CE8 DBBBC2DB
   04DE8EF9 2E8EFC14 1FBECAA6 287C5947 4E6BC05D 99B2964F A090C3A2
   233BA186 515BE7ED 1F612970 CEE2D7AF B81BDD76 2170481C D0069127
   D5B05AA9 93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34028492
   36C3FAB4 D27C7026 C1D4DCB2 602646DE C9751E76 3DBA37BD F8FF9406
   AD9E530E E5DB382F 413001AE B06A53ED 9027D831 179727B0 865A8918
   DA3EDBEB CF9B14ED 44CE6CBA CED4BB1B DB7F1447 E6CC254B 33205151
   2BD7AF42 6FB8F401 378CD2BF 5983CA01 C64B92EC F032EA15 D1721D03
   F482D7CE 6E74FEF6 D55E702F 46980C82 B5A84031 900B1C9E 59E7C97F
   BEC7E8F3 23A97A7E 36CC88BE 0F1D45B7 FF585AC5 4BD407B2 2B4154AA
   CC8F6D7E BF48E1D8 14CC5ED2 0F8037E0 A79715EE F29BE328 06A1D58B
   B7C5DA76 F550AA3D 8A1FBFF0 EB19CCB1 A313D55C DA56C9EC 2EF29632
   387FE8D7 6E3C0468 043E8F66 3F4860EE 12BF2D5B 0B7474D6 E694F91E
   6DCC4024 FFFFFFFF FFFFFFFF

```

as group order (6144 bit), with 2 as generator of the group, following the indication of 

https://www.ietf.org/rfc/rfc3526.txt

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

![deep think](https://media.giphy.com/media/BmmfETghGOPrW/giphy.gif)


## Scram-SHA256

We have added session feature so that the Server can store Clients data with the aim to prevent possible attacks, such as replay attack. Furthermore, we have added a TTL (time to live) parameter so that sessions will be removed after 10 seconds. We have added an abstract class for the storage so that one can choose the type of structure to use for saving Server records. Lastly, we have simplified some notation used in SCRAM RFC, while maintaining the original mechanism and purpose. In particular, we have decided to use the SCRAM variant with SHA256, instead of the original SHA1.


## References
[Solar Designer inspiration tweet](https://twitter.com/solardiz/status/965599513497960449)

[Kai Dietrich explanation blog post](https://www.cleeus.de/w/blog/2018/02/13/The_SCRAM_Authentication_Protocol.html)

[MongoDB blog post](https://www.mongodb.com/blog/post/improved-password-based-authentication-mongodb-30-scram-explained-part-1?jmp=docs)

## LICENCE

This program is free software; you can redistribute it and/or modify it under the terms of the [GNU General Public License](https://www.gnu.org/licenses/gpl-3.0.html) as published by the Free Software Foundation; either version 3 of the License, or(at your option) any later version.