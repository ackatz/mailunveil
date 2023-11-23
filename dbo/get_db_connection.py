import os
import MySQLdb


def get_db_connection():
    # Connect to the MySQL database
    connection = MySQLdb.connect(
        host=os.environ.get("DATABASE_HOST"),
        user=os.environ.get("DATABASE_USERNAME"),
        passwd=os.environ.get("DATABASE_PASSWORD"),
        db=os.environ.get("DATABASE"),
        autocommit=True,
        ssl_mode="VERIFY_IDENTITY",
        ssl={"ca": "/etc/ssl/certs/ca-certificates.crt"},
    )

    try:
        return connection

    except MySQLdb.Error as e:
        print("MySQL Error:", e)
