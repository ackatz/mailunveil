import dns.resolver


async def clean_dns_text_record(record: str) -> str:
    return record.replace('"', "").strip('"')


async def check(domain: str):
    # Set default values to an empty string or a specific message
    mx_record = False
    spf_record = False
    dmarc_record = False
    spoofable = False

    try:
        # Get the MX record for the domain
        mx_records = dns.resolver.resolve(domain, "MX")
        mx_record = str(mx_records[0].exchange).rstrip(".")
    except:
        pass

    try:
        # Get the SPF record for the domain
        spf_records = dns.resolver.resolve(domain, "TXT")
        for txt_record in spf_records:
            if txt_record.to_text().startswith('"v=spf1'):
                spf_record_raw = txt_record.to_text()
                spf_record = await clean_dns_text_record(spf_record_raw)
                # Check if the SPF policy is too permissive
                if "+all" in spf_record_raw:
                    spoofable = True
                break
    except:
        # No SPF record found, domain might be spoofable
        spoofable = True

    try:
        # Get the DMARC record for the domain
        dmarc_records = dns.resolver.resolve("_dmarc." + domain, "TXT")
        for txt_record in dmarc_records:
            if txt_record.to_text().startswith('"v=DMARC1'):
                dmarc_record_raw = txt_record.to_text()
                dmarc_record = await clean_dns_text_record(dmarc_record_raw)
                # Check if the DMARC policy is set to none
                if "p=none" in dmarc_record_raw:
                    spoofable = True
                break
    except:
        # No DMARC record found, domain might be spoofable
        spoofable = True

    return mx_record, spf_record, dmarc_record, spoofable
