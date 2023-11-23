import dns.resolver


async def check(domain):
    query_domain = ".".join(reversed(domain.split("."))) + ".dbl.spamhaus.org"

    try:
        dns.resolver.resolve(query_domain, "A")
        return True
    except dns.resolver.NXDOMAIN:
        return False
    except dns.resolver.Timeout:
        return False
    except Exception as e:
        return False
