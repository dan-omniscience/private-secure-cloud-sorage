import os, time
from hashing import sha256_checksum
from datetime import datetime, timedelta
from multiprocessing.pool import ThreadPool

MAX_THREADS = 64

flatten = lambda l: [item for sublist in l for item in sublist]

def modification_date(filename):
    t = os.path.getmtime(filename)
    return datetime.datetime.fromtimestamp(t)

def timing(f):
    def wrap(*args):
        time1 = time.time()
        ret = f(*args)
        time2 = time.time()
        print '%s function took %0.3f ms' % (f.func_name, (time2-time1)*1000.0)
        return ret
    return wrap


def hash_worker(file_path):
    file_sha256 = sha256_checksum(file_path)
    return file_sha256

# @timing
def scan(path, db, force = False):
    should_scan = False
    conn = db.get_conn()
    c = conn.cursor()
    c.execute('''SELECT value as "[timestamp]" FROM settings WHERE key = "last_scan" AND path = ?''', (path,) )
    last_scan_record = c.fetchone()
    c.execute('''SELECT count(*) as "[int]" FROM files WHERE last_backup IS NOT NULL''')
    backup_count = c.fetchone()[0]

    if last_scan_record is None or last_scan_record[0] is None:
        c.execute('''INSERT INTO settings (path, key, value) VALUES (?, "last_scan", ?)''', (path, datetime.now(),))
        conn.commit()
        should_scan = True
    else:
        last_scan = last_scan_record[0]
        c.execute('''UPDATE settings SET value = ? WHERE key ="last_scan" AND path = ?''', (datetime.now(), path, ))
        conn.commit()
        should_scan = datetime.now() - last_scan > timedelta(hours=1)
    if should_scan or force:
        all_files = []
        all_keys = []

        for dirname, dirnames, filenames in os.walk(path):
            # Ignore dot files
            filenames = filter(lambda x: x[0:1] != ".", filenames)
            filenames = map(lambda x: os.path.join(dirname, x), filenames)
            keys = map(lambda x: x.replace(path, "").decode('utf8'), filenames)

            all_files = list(set().union(all_files, filenames))
            all_keys = list(set().union(all_keys, keys))

        if len(all_keys) > backup_count:
            all_records = zip(all_files, all_keys)
            query = '''SELECT key as "[str]" FROM files WHERE key NOT IN ({0})'''.format(", ".join(map(lambda x: "?", all_keys)))
            c.execute(query, all_keys)
            new_keys = c.fetchall()
            new_keys = map(lambda x: x[0], new_keys)
            new_records = map(lambda x: list(x), filter(lambda x: x[1] in new_keys, all_records))
            new_keys = map(lambda x: x[1], new_records)
            chunks = [new_records[x:x + 250] for x in xrange(0, len(new_records), 250)]
            for new_records_chunk in chunks:
                query = u'INSERT INTO files (full_path, key) VALUES {0}'.format(u', '.join(map(lambda x: u'(?, ?)', new_records_chunk)))
                flat_new_records_chunk = flatten(new_records_chunk)
                c.execute(query, flat_new_records_chunk)
            conn.commit()

        c.execute('''SELECT * FROM files WHERE sha256 IS NULL''')
        waiting_for_hashing_or_backup = c.fetchall()
        waiting_for_hashing_or_backup_chunks = [waiting_for_hashing_or_backup[x:x + MAX_THREADS] for x in xrange(0, len(waiting_for_hashing_or_backup), MAX_THREADS)]
        for waiting_for_hashing_or_backup_chunk in waiting_for_hashing_or_backup_chunks:
            pool = ThreadPool(processes=MAX_THREADS)
            files_hashs = pool.map(hash_worker, map(lambda x: x[1], waiting_for_hashing_or_backup_chunk))
            for i in range(len(waiting_for_hashing_or_backup_chunk)):
                c.execute(u'''UPDATE files SET sha256 = ? WHERE key = ?;''', (files_hashs[i], waiting_for_hashing_or_backup_chunk[i][0], ))
            conn.commit()
            time.sleep(1)