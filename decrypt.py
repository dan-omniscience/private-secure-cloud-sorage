import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto import Random
import os.path
import base64
import time
from tqdm import tqdm
import hashlib
import sys
import boto3
from Queue import Queue
from threading import Thread
from multiprocessing import Queue
from Queue import Queue
from generate_encryption_keys import get_encryption_keys
# GLOBALS
THREADS = 32
database_path = "./.database.db"

decrypted_queue = None
q = None

database = None
threads_pool = None
decryptionCipher = None
enc_secret = None
privatekey_path = "./private-key.pem"
publickey_path = "./public-key.pem"
encrypted_files_output = "./encrypted/"
decrypted_files_output = "./decrypted/"
unpad = lambda s : s.rstrip(s[-1])

def save_decrypted():
    while True:
        plain_content, output_path = decrypted_queue.get()
        if plain_content is not None and output_path is not None:
            with open(output_path, "w") as f:
                f.write(plain_content)
                decrypted_queue.task_done()

def decrypt_worker():
    while True:
        encrypted_content, enc_secret, output_path = q.get()
        if encrypted_content is not None and enc_secret is not None and output_path is not None:
            secret = decryptionCipher.decrypt(enc_secret)
            iv = encrypted_content[-16::]
            decryption = AES.new(secret, AES.MODE_CBC, iv)
            decrypted_queue.put((base64.b64decode(unpad(decryption.decrypt(encrypted_content)[0:-16])), output_path),)
            q.task_done()

def timing(f):
    def wrap(*args):
        time1 = time.time()
        ret = f(*args)
        time2 = time.time()
        print '%s function took %0.3f ms' % (f.func_name, (time2-time1)*1000.0)
        return ret
    return wrap

def sha256_checksum(file_path, block_size=65536):
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest()


# Decrypt
def decrypt_file(file_path):
    output_file = file_path.replace(encrypted_files_output, decrypted_files_output).replace(".enc", "")
    try:
        os.makedirs(os.path.dirname(output_file))
    except:
        pass

    with open(file_path, "r") as f:
        encrypted_content = f.read()
        q.put((encrypted_content, enc_secret, output_file), )

if __name__ == "__main__":
    privatekey, publickey, enc_secret = get_encryption_keys(privatekey_path, publickey_path)
    decryptionCipher = PKCS1_OAEP.new(privatekey)
    decrypted_queue = Queue(maxsize=0)
    q = Queue(maxsize=0)
    for i in range(THREADS):
        t = Thread(target=decrypt_worker)
        t.daemon = True
        t.start()
    for i in range(THREADS):
        t = Thread(target=save_decrypted)
        t.daemon = True
        t.start()
    for dirname, dirnames, filenames in os.walk(encrypted_files_output):
        # print path to all filenames.
        for filename in filenames:
            if(filename[0:1] != "."):
                decrypt_file(os.path.join(dirname, filename))
    q.join()
    decrypted_queue.join()