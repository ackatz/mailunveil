import whois
from datetime import datetime


async def check(domain: str) -> int:
    try:
        domain_info = whois.whois(domain)
        creation_date = (
            domain_info.creation_date[0]
            if type(domain_info.creation_date) is list
            else domain_info.creation_date
        )
        if creation_date:
            # Calculate the difference between now and the creation date
            return (datetime.now() - creation_date).days
        else:
            return -1  # If creation date is not available
    except Exception as e:
        print(f"An error occurred: {e}")
        return -1
