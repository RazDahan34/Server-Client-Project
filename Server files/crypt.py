from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

AES_KEY_SIZE = 32  # 256 bits
RSA_KEY_SIZE = 1024  # 1024 bits

def generate_aes_key():
    """
    Generates a random AES key for symmetric encryption. This key is used for
    encrypting file contents and other sensitive data that needs to be transmitted
    securely between the client and server.
    """
    return get_random_bytes(AES_KEY_SIZE)

def encrypt_aes(data, key):
    """
    Encrypts data using AES in CBC mode. This function is used to secure file
    contents and other sensitive information before transmission. It automatically
    generates an IV (Initialization Vector) for added security.
    """
    cipher = AES.new(key, AES.MODE_CBC)  # IV is automatically generated
    return cipher.iv + cipher.encrypt(pad(data, AES.block_size))

def decrypt_aes(data, key):
    """
    Decrypts data that was encrypted using AES in CBC mode. This function is used
    to recover the original content of encrypted files or messages received from
    clients. It handles the IV and unpadding automatically.
    """
    iv = data[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data[AES.block_size:]), AES.block_size)

def generate_rsa_key():
    """
    Generates an RSA key pair for asymmetric encryption. This is typically used
    for secure key exchange, where the public key is shared with clients, and the
    private key is kept secret on the server.
    """
    return RSA.generate(RSA_KEY_SIZE)

def encrypt_aes_key(aes_key, public_key):
    """
    Encrypts an AES key using an RSA public key. This is used in the key exchange
    process, where the server needs to securely send an AES key to a client. The
    AES key is encrypted with the client's public RSA key.
    """
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.encrypt(aes_key)

def decrypt_aes_key(encrypted_aes_key, private_key):
    """
    Decrypts an AES key that was encrypted with an RSA public key. This is used
    by clients to recover the AES key sent by the server, using their private RSA key.
    """
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.decrypt(encrypted_aes_key)