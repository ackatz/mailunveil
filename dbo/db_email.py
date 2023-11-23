from app.dbo.get_db_connection import get_db_connection
import MySQLdb


async def insert_or_update(email_info):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO emails (email_address, reputation_score, reputation_text, valid, deliverable, spoofable)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
            reputation_score = VALUES(reputation_score),
            reputation_text = VALUES(reputation_text),
            valid = VALUES(valid),
            deliverable = VALUES(deliverable),
            spoofable = VALUES(spoofable)
            """,
            email_info,
        )
    except MySQLdb.Error as e:
        print(f"MySQL Error during email insert/update: {e}")
    cursor.close()
    return cursor.lastrowid  # Return the last inserted id
