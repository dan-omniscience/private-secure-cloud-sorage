import os.path, errno, Crypto
from getpass import getpass
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random

private_key_filename = "s3-encrypt-sync_private-key.pem"
public_key_filename = "s3-encrypt-sync_public-key.pem"

class KeysExists(IOError):
    errno = errno.EEXIST
    message = "Keys Already Exists"

def generate_keys(certs_paths, password_file = ".secret"):
    private_key_path = os.path.join(certs_paths, private_key_filename)
    public_key_path = os.path.join(certs_paths, public_key_filename)
    if os.path.isfile(public_key_path) and os.path.isfile(private_key_path):
        raise KeysExists()
    else:
        random_generator = Random.new().read
        privatekey = RSA.generate(2048, random_generator) #generate pub and priv key
        with open(private_key_path, "w") as f:
            f.write(privatekey.exportKey("PEM"))
        publickey = privatekey.publickey() # pub key export for exchange
        with open(public_key_path, "w") as f:
            f.write(publickey.exportKey("PEM"))
        os.chmod(private_key_path, 0400)
        os.chmod(public_key_path, 0644)

    if not os.path.isfile(password_file):
        secret = getpass("Enter a 32 byte password:")
        encryptionCipher = PKCS1_OAEP.new(publickey)
        with open(password_file, "w") as f:
            enc_secret = encryptionCipher.encrypt(secret)
            f.write(enc_secret)