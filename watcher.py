from hashing import sha256_checksum
from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler
from watchdog.events import FileSystemEventHandler


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