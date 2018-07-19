import sqlite3
from datetime import datetime

class Database(object):
    _database = None

    def __new__(cls, *args, **kwargs):
        if not cls._database:
            cls._database = super(Database, cls).__new__(
                cls, *args, **kwargs)
        return cls._database

    def __init__(self, database_path):
        self._database = sqlite3.connect(database_path, detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)
        self._database.text_factory = unicode

    def get_conn(self): return self._database

    def get_cursur(self): return self.get_conn().cursor()

    def init_database(self):
        c = self.get_cursur()
        c.execute('''CREATE TABLE IF NOT EXISTS migrations (
                batch INTEGER NOT NULL,
                migrated_at TEXT NOT NULL
                );''')
        c.execute('''CREATE TABLE IF NOT EXISTS files (
            key TEXT NOT NULL,
            full_path TEXT NOT NULL,
            sha256 TEXT,
            last_backup TEXT
            );''')
        c.execute('''CREATE UNIQUE INDEX IF NOT EXISTS idx_key ON files (key);''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_sha256 ON files (sha256);''')
        c.execute('''CREATE TABLE IF NOT EXISTS settings (
                path TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL
                );''')
        c.execute('''INSERT INTO migrations (batch, migrated_at) VALUES (1, ?)''', (datetime.now(),))
        self._database.commit()

    def get_version(self):
        c = self.get_cursur()
        c.execute('''SELECT * FROM migrations ORDER BY batch DESC''')
        r = c.fetchone()
        return r[0]

    def update_database(self):
        c = self.get_cursur()
        c.execute('''SELECT * FROM migrations ORDER BY batch DESC''')
        r = c.fetchone()
        current_ver = 0;
        if r is not None:
            current_ver = r[0]

            # if current_ver < 2:
            #     pass