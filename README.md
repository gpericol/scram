header: "Luca Zanolini CUEA"

registrazione:
client -> username,client_nonce, n

server -> server_salt, ic, g, client_nonce, server_nonce

client -> saltedpassword ^ shared

server genera Clientkey, ServerKey, StoredKey


client genera ClientKey, ServerKey



verifica:

client -> header,username,client_nonce
server -> client_nonce, server_nonce, salt, ic

AuthMessage     := username,client-nonce,salt,ic,server-nonce
ClientSignature := HMAC(StoredKey, AuthMessage)
ClientProof     := ClientKey XOR ClientSignature

client -> ClientProof

server -> ServerSignature