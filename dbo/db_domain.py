from app.dbo.get_db_connection import get_db_connection
import MySQLdb


async def insert_or_update(domain_info):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO domains (domain_name, tld, primary_mx, spf_record, dmarc_record, days_since_creation, 
            new_domain, disposable, spam, phishing, suspicious, catch_all)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
            tld = VALUES(tld),
            primary_mx = VALUES(primary_mx),
            spf_record = VALUES(spf_record),
            dmarc_record = VALUES(dmarc_record),
            days_since_creation = VALUES(days_since_creation),
            new_domain = VALUES(new_domain),
            disposable = VALUES(disposable),
            spam = VALUES(spam),
            phishing = VALUES(phishing),
            suspicious = VALUES(suspicious),
            catch_all = VALUES(catch_all)
            """,
            domain_info,
        )
    except MySQLdb.Error as e:
        print(f"MySQL Error during domain insert/update: {e}")
    cursor.close()
    return cursor.lastrowid  # Return the last inserted id
