from app.dbo.get_db_connection import get_db_connection
import MySQLdb
from typing import Tuple
from datetime import datetime


def datetime_to_string(datetime) -> str:
    """Convert a datetime object to a string in ISO 8601 format."""
    return datetime.strftime("%Y-%m-%dT%H:%M:%S") if datetime else None


async def check(email: str) -> Tuple[str, str]:
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT first_seen, last_updated FROM emails WHERE email_address = %s
            """,
            (email,),
        )
        result = cursor.fetchone()
        if result:
            return datetime_to_string(result[0]), datetime_to_string(result[1])
        else:
            return "Never", "Never"
    except MySQLdb.Error as e:
        print("MySQL Error:", e)
        return "Never", "Never"
