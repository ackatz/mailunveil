from typing import Union
import re
import json
from fastapi import FastAPI, Request, Form, Body, HTTPException
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.templating import Jinja2Templates
from starlette.staticfiles import StaticFiles
from app.email_functions import (
    smtp,
    mx_spf_dmarc,
    spamhaus_dbl,
    whois_domain_creation,
    reputation,
    random_email,
)
import time
import bleach
from app.dbo import db_domain, db_email, db_history
from slowapi import Limiter
from pydantic import BaseModel


class EmailRequestBody(BaseModel):
    email: str | None = None


def get_real_address(request: Request) -> Union[str, None]:
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        real_ip = forwarded_for.split(",")[0]
    else:
        real_ip = request.client.host
    return real_ip


app = FastAPI(
    redoc_url=None,
    description="""
              MailUnveil.com API - Check the reputation of an email address
              
## Usage

### Web Interface

Visit [MailUnveil.com](https://mailunveil.com) to use the web interface.

### API

The API is available at https://mailunveil.com/api/v1/check

#### Request

The API accepts a POST request with a JSON body containing the email address to check. Requests are limited to 10 per minute.

```json
{
    "email": "example@example.org"
}
```
              """,
    docs_url="/docs",
    title="MailUnveil.com",
    version="1.0.0",
    openapi_url="/api/v1/openapi.json",
)
limiter = Limiter(key_func=get_real_address, headers_enabled=True)

templates = Jinja2Templates(directory="/app/templates")
app.mount("/app/static", StaticFiles(directory="/app/static"), name="static")

# Load disposable email domains at runtime
with open("/app/lists/disposable_domains.txt", "r") as f:
    disposable_domains = set(f.read().splitlines())

# Load phishing domains at runtime
with open("/app/lists/phishing_domains.txt", "r") as f:
    phishing_domains = set(f.read().splitlines())

# Load malicious domains at runtime
with open("/app/lists/malicious_domains.txt", "r") as f:
    malicious_domains = set(f.read().splitlines())

# Load suspicious TLDs at runtime
with open("/app/tlds/suspicious_tlds.txt", "r") as f:
    suspicious_tlds = set(f.read().splitlines())


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def get(request: Request):
    context = {"request": request}
    return templates.TemplateResponse("index.html", context)


@app.post("/index_check", response_class=JSONResponse, include_in_schema=False)
@limiter.limit("10/minute")
async def page_check(request: Request, response: Response, email: str = Form(...)):
    start_time = time.time()

    email = bleach.clean(email)

    match = re.match(
        "^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$",
        email.lower(),
    )

    if match:
        # Format domain

        domain = email.split("@")[1]

        # Check for suspicious TLDs

        suspicious_tld = domain.split(".")[-1] in suspicious_tlds

        # Check MX, SPF, DMARC

        mx_record, spf_record, dmarc_record, spoofable = await mx_spf_dmarc.check(
            domain
        )

        # Check SMTP

        deliverable, catch_all = smtp.check(email, mx_record, domain)

        # Check Spamhaus DBL

        spam_domain = await spamhaus_dbl.check(email)

        # Check Phishing Domains

        phishing_domain = (
            domain.lower() in phishing_domains or domain.lower() in malicious_domains
        )

        # Check if disposable email

        disposable_domain = domain.lower() in disposable_domains

        # Check days since domain creation

        domain_days_since_creation = await whois_domain_creation.check(domain)

        # Check for email randomness

        randomness = await random_email.check(email)

        # Check reputation

        reputation_text, score = await reputation.check(
            spf_record,
            dmarc_record,
            spam_domain,
            phishing_domain,
            disposable_domain,
            domain_days_since_creation < 30,
            suspicious_tld,
            spoofable,
            deliverable,
            catch_all,
            randomness,
        )

        domain_info = (
            domain,
            domain.split(".")[-1],
            mx_record,
            spf_record,
            dmarc_record,
            domain_days_since_creation,
            domain_days_since_creation < 30,
            disposable_domain,
            spam_domain,
            phishing_domain,
            suspicious_tld,
            catch_all,
        )

        await db_domain.insert_or_update(domain_info)

        email_info = (
            email,
            score,
            reputation_text,
            match is not None,
            deliverable,  # This should be updated with the actual check
            spoofable,
        )

        await db_email.insert_or_update(email_info)

        first_seen, last_updated = await db_history.check(email)

        end_time = time.time()

        response_time = end_time - start_time

    else:
        end_time = time.time()

        response_time = end_time - start_time

        formatted_json = json.dumps(
            {
                "status": 400,
                "response_time": round(response_time, 2),
                "error": "Invalid email address",
            },
            indent=2,
        )
        return Response(
            content=formatted_json, media_type="application/json", status_code=400
        )

    formatted_json = json.dumps(
        {
            "status": 200,
            "response_time": round(response_time, 2),
            "data": {
                "email": {
                    "address": email,
                    "valid": match is not None,
                    "deliverable": deliverable,
                    "spoofable": spoofable,
                    "first_seen": first_seen,
                    "last_updated": last_updated,
                },
                "domain": {
                    "domain_name": domain,
                    "tld": domain.split(".")[-1],
                    "suspicious_tld": suspicious_tld,
                    "primary_mx": mx_record,
                    "spf_record": spf_record,
                    "dmarc_record": dmarc_record,
                    "catch_all": catch_all,
                    "domain_days_since_creation": domain_days_since_creation,
                    "new_domain": domain_days_since_creation < 30,
                    "disposable_domain": disposable_domain,
                    "spam_domain": spam_domain,
                    "phishing_domain": phishing_domain,
                },
                "reputation": {
                    "text": reputation_text,
                    "score": score,
                },
            },
        },
        indent=2,
    )

    return Response(
        content=formatted_json, media_type="application/json", status_code=200
    )


@app.post(
    "/api/v1/check",
    response_class=JSONResponse,
    summary="Check the reputation of an email address",
    description="Check the reputation of an email address",
    response_description="Returns a JSON object containing the reputation of the email address",
    tags=["API"],
    include_in_schema=True,
    responses={
        200: {
            "description": "Successful response",
            "content": {
                "application/json": {
                    "example": {
                        "status": 200,
                        "response_time": 0.5,
                        "data": {
                            "email": {
                                "address": "example@example.org",
                                "valid": True,
                                "deliverable": True,
                                "spoofable": False,
                                "first_seen": "2021-01-01 00:00:00",
                                "last_updated": "2021-01-01 00:00:00",
                            },
                            "domain": {
                                "domain_name": "example.org",
                                "tld": "org",
                                "suspicious_tld": False,
                                "primary_mx": "mx.example.org",
                                "spf_record": "v=spf1 mx -all",
                                "dmarc_record": "v=DMARC1; p=reject; rua=mailto:",
                                "catch_all": False,
                                "domain_days_since_creation": 365,
                                "new_domain": False,
                                "disposable_domain": False,
                                "spam_domain": False,
                                "phishing_domain": False,
                            },
                            "reputation": {
                                "text": "good",
                                "score": 0,
                            },
                        },
                    }
                }
            },
        },
        400: {
            "description": "Invalid email address",
            "content": {
                "application/json": {
                    "example": {
                        "status": 400,
                        "response_time": 0.5,
                        "error": "Invalid email address",
                    }
                }
            },
        },
        429: {
            "description": "Too many requests",
            "content": {
                "application/json": {
                    "example": {"status": 429, "detail": "10 per 1 minute"}
                }
            },
        },
    },
)
@limiter.limit("10/minute")
async def api_check(
    request: Request,
    response: Response,
    email_body: EmailRequestBody = Body(default=None),
):
    email = email_body.email

    if not email:
        return JSONResponse(status_code=400, content={"error": "No email provided"})

    email = bleach.clean(email)

    start_time = time.time()

    match = re.match(
        "^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$",
        email.lower(),
    )

    if match:
        # Format domain

        domain = email.split("@")[1]

        # Check for suspicious TLDs

        suspicious_tld = domain.split(".")[-1] in suspicious_tlds

        # Check MX, SPF, DMARC

        mx_record, spf_record, dmarc_record, spoofable = await mx_spf_dmarc.check(
            domain
        )

        # Check SMTP

        deliverable, catch_all = smtp.check(email, mx_record, domain)

        # Check Spamhaus DBL

        spam_domain = await spamhaus_dbl.check(email)

        # Check Phishing Domains

        phishing_domain = (
            domain.lower() in phishing_domains or domain.lower() in malicious_domains
        )

        # Check if disposable email

        disposable_domain = domain.lower() in disposable_domains

        # Check days since domain creation

        domain_days_since_creation = await whois_domain_creation.check(domain)

        # Check for email randomness

        randomness = await random_email.check(email)

        # Check reputation

        reputation_text, score = await reputation.check(
            spf_record,
            dmarc_record,
            spam_domain,
            phishing_domain,
            disposable_domain,
            domain_days_since_creation < 30,
            suspicious_tld,
            spoofable,
            deliverable,
            catch_all,
            randomness,
        )

        domain_info = (
            domain,
            domain.split(".")[-1],
            mx_record,
            spf_record,
            dmarc_record,
            domain_days_since_creation,
            domain_days_since_creation < 30,
            disposable_domain,
            spam_domain,
            phishing_domain,
            suspicious_tld,
            catch_all,
        )

        await db_domain.insert_or_update(domain_info)

        email_info = (
            email,
            score,
            reputation_text,
            match is not None,
            deliverable,  # This should be updated with the actual check
            spoofable,
        )

        await db_email.insert_or_update(email_info)

        first_seen, last_updated = await db_history.check(email)

        end_time = time.time()

        response_time = end_time - start_time

    else:
        end_time = time.time()

        response_time = end_time - start_time

        formatted_json = json.dumps(
            {
                "status": 400,
                "response_time": round(response_time, 2),
                "error": "Invalid email address",
            },
            indent=2,
        )
        return Response(
            content=formatted_json, media_type="application/json", status_code=400
        )

    formatted_json = json.dumps(
        {
            "status": 200,
            "response_time": round(response_time, 2),
            "data": {
                "email": {
                    "address": email,
                    "valid": match is not None,
                    "deliverable": deliverable,
                    "spoofable": spoofable,
                    "first_seen": first_seen,
                    "last_updated": last_updated,
                },
                "domain": {
                    "domain_name": domain,
                    "tld": domain.split(".")[-1],
                    "suspicious_tld": suspicious_tld,
                    "primary_mx": mx_record,
                    "spf_record": spf_record,
                    "dmarc_record": dmarc_record,
                    "catch_all": catch_all,
                    "domain_days_since_creation": domain_days_since_creation,
                    "new_domain": domain_days_since_creation < 30,
                    "disposable_domain": disposable_domain,
                    "spam_domain": spam_domain,
                    "phishing_domain": phishing_domain,
                },
                "reputation": {
                    "text": reputation_text,
                    "score": score,
                },
            },
        },
        indent=2,
    )

    return Response(
        content=formatted_json, media_type="application/json", status_code=200
    )
