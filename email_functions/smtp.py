import smtplib
import random
import string
import socket


def generate_random_email(domain: str) -> str:
    random_username = "".join(random.choices(string.ascii_lowercase, k=20))
    return f"{random_username}@{domain}"


def check(email: str, mx_record: str, domain: str):
    try:
        random_email = generate_random_email(domain)
        server = smtplib.SMTP(mx_record)

        # SMTP conversation
        server.set_debuglevel(0)
        server.ehlo()
        server.mail("")

        primary_response = server.rcpt(email)
        random_email_response = server.rcpt(random_email)
        server.quit()

        primary_code = primary_response[0]
        random_email_code = random_email_response[0]

        if primary_code == 250 and random_email_code == 250:
            return True, True  # Email exists and domain is a catch-all
        elif primary_code == 550 and random_email_code == 250:
            return False, True  # Email does not exist but domain is a catch-all
        elif primary_code == 250 and random_email_code == 550:
            return True, False  # Email exists and domain is not a catch-all
        else:
            return False, False  # Email does not exist and domain is not a catch-all
    except (socket.gaierror, socket.error, socket.herror, smtplib.SMTPException) as e:
        print(f"SMTP Error: {e}")
        return False, False
