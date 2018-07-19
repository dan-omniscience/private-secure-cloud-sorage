import sys, getopt, logging, errno
from os.path import expanduser
from generate_encryption_keys import generate_keys
from database import Database
from scanner import scan
# from encrypt import encrypt

certs_paths = expanduser("~/.ssh")
database_path = expanduser("~/.s3-encrypt-sync-database.db")

def main(argv):
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    try:
        opts, args = getopt.getopt(argv, "hgw:vs:u", ["generate-keys", "watch", "init-database", "migrate-database", "scan", "upload"])
    except getopt.GetoptError:
        print 'test.py [OPTIONS]'
        print "\n".join([
            "--init-database\t-\t Inital Database Setup",
            "--migrate-database\t-\t Update Databse to latest version"
        ])
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print 'main.py -g <cert_paths>'
            print 'main.py -w <path>'
            sys.exit()
        elif opt in ("--init-database"):
            db = Database(database_path)
            db.init_database()
        elif opt in ("-v", "--version"):
            db = Database(database_path)
            print "Version: {0}".format(db.get_version())
        elif opt in ("--migrate-database"):
            db = Database(database_path)
            db.init_database()
            print "Succesfully Created Database as {0}".format(database_path)
        elif opt in ("-g", "--generate-keys"):
            try:
                generate_keys(certs_paths)
                print "Keys Generated at {0}".format(certs_paths)
            except IOError as e:
                if e.errno == errno.EEXIST:
                    print('Keys was not generated {0}'.format(e.message))
        elif opt in ("-s", "--scan"):
            db = Database(database_path)
            if arg != "":
                scan(arg, db, True)
            else:
                print "Missing path to scan"
        elif opt in ("-u", "--upload"):
            db = Database(database_path)




if __name__ == "__main__":
    main(sys.argv[1:])


