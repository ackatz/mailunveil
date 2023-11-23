FROM python:3.11-slim as builder

RUN apt-get update && apt-get install -y wget curl tar --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /app/lists \
    && wget -qO /app/lists/disposable_domains.txt https://github.com/FGRibreau/mailchecker/blob/master/list.txt

RUN wget -qO - https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/ALL-phishing-domains.tar.gz | tar -xzO > /app/lists/phishing_domains.txt

RUN wget -qO /app/lists/malicious_domains.txt https://dangerous.domains/list.txt

COPY . /app

FROM python:3.11-slim

COPY --from=builder /app /app
COPY --from=builder /app/lists /app/lists

ENV PATH="/home/app/.local/bin:${PATH}"
ENV PYTHONUNBUFFERED=1

RUN addgroup --system app && adduser --system --group app --home /app

RUN apt update && apt install -y pkg-config default-libmysqlclient-dev ca-certificates build-essential libssl-dev libffi-dev libmagic1 --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --upgrade wheel
RUN pip install --upgrade -r /app/requirements/app.txt

RUN chmod +x /app/run.sh && mkdir /app/log && chown -R app:app /app

EXPOSE 8000

USER app

CMD [ "/app/run.sh" ]
