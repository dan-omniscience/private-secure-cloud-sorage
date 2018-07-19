import os.path, base64, time, hashlib, sys, logging, boto3
from multiprocessing.pool import ThreadPool
from database import Database
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto import Random,

from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler
from watchdog.events import FileSystemEventHandler
from Queue import Queue
from threading import Thread, Semaphore
from Queue import Queue
from generate_encryption_keys import get_encryption_keys
from datetime import datetime, timedelta

# GLOBALS
THREADS = 32
MAX_THREADS = 128
database_path = "./.database.db"


db = Database(database_path)
# s3 = boto3.resource('s3')
lock = Semaphore(1)
encrypted_queue = None
q = None
database = None
decryptionCipher = None
enc_secret = None
privatekey_path = "./private-key.pem"
publickey_path = "./public-key.pem"
path_to_encrypt = "./data/"
path = None
encrypted_files_output = "./encrypted/"
password_file = ".secret"
bucket_name = "storage.omniscience.co.il"
prefix = "home/Pictures"
BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)

def upload_encrypted():
    while True:
        encrypted_content, key = encrypted_queue.get()
        if encrypted_content is not None and key is not None:
            s3.Object(bucket_name, prefix + key + ".enc").put(Body=encrypted_content)
            c = db.get_cursur()
            c.execute('''UPDATE files SET last_backup = ?''', (datetime.now(),))
            conn.commit()
            with lock:
                print  "uploaded %s to s3 at %s/%s.enc" % (key, bucket_name, prefix + key)
            encrypted_queue.task_done()

def encrypt_worker():
    while True:
        plain_content, enc_secret, key = q.get()
        if plain_content is not None and enc_secret is not None and key is not None:
            secret = decryptionCipher.decrypt(enc_secret)
            iv = Random.new().read(16)
            encryption = AES.new(secret, AES.MODE_CBC, iv)
            encrypted_queue.put((encryption.encrypt(pad(plain_content)) + iv, key), )
            q.task_done()
# Encrypt
def encrypt_file(file_path, key):
    with open(file_path, "r") as f:
        content = base64.b64encode(f.read())
        q.put((content, enc_secret, key), )

class MyHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if not event.is_directory and os.path.basename(event.src_path)[0:1] != ".":
            c = db.get_cursur()
            file_sha256 = sha256_checksum(event.src_path)
            key = event.src_path.replace(path, "").decode('utf8')
            c.execute('''SELECT * FROM files WHERE key = ?''', (key, ))
            r = c.fetchone()
            if r is None:
                print("event type: %s path : %s" % (event.event_type, event.src_path))
                c.execute('''INSERT INTO files (key, sha256) VALUES (?, ?)''', (key, file_sha256, ))
                conn.commit()
                encrypt_file(event.src_path, key)
            elif r[1] != file_sha256:
                print("event type: %s path : %s" % (event.event_type, event.src_path))
                c.execute('''UPDATE files SET sha256 = ? WHERE key = ?''', (file_sha256, key, ))
                conn.commit()
                encrypt_file(event.src_path, key)
            elif r[2] is None:
                encrypt_file(event.src_path, key)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
    path = sys.argv[1] if len(sys.argv) > 1 else path_to_encrypt
    privatekey, publickey, enc_secret = get_encryption_keys(privatekey_path, publickey_path)
    decryptionCipher = PKCS1_OAEP.new(privatekey)
    event_handler = MyHandler()
    encrypted_queue = Queue(maxsize=10)
    q = Queue(maxsize=10)
    
    for i in range(THREADS):
        t = Thread(target=encrypt_worker)
        t.daemon = True
        t.start()
    for i in range(THREADS):
        t = Thread(target=upload_encrypted)
        t.daemon = True
        t.start()

    for dirname, dirnames, filenames in os.walk(path):
        # print path to all filenames.
        for filename in filenames:
            if(filename[0:1] != "."):
                file_path = os.path.join(dirname, filename)
                key =file_path.replace(path, "").decode('utf8')
                c = database.cursor()
                c.execute('''SELECT * FROM files WHERE key = ?''', (key, ))
                backup = c.fetchone()
                if backup is None:
                    file_sha256 = sha256_checksum(file_path)
                    print("event type: uploading a file : %s" % (file_path))
                    c.execute('''INSERT INTO files (key, sha256) VALUES (?, ?)''', (key, file_sha256, ))
                    database.commit()
                    encrypt_file(file_path, key)
                elif backup[2] is None:
                    file_sha256 = sha256_checksum(file_path)
                    print("event type: uploading a file : %s" % (file_path))
                    c.execute('''UPDATE files SET sha256 = ? WHERE key = ?''', (file_sha256, key, ))
                    database.commit()
                    encrypt_file(file_path, key)

    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
    q.join()
    encrypted_queue.join()