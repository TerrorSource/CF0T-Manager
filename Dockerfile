FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    CF0T_DATA_DIR=/data \
    PUID=1000 \
    PGID=1000

WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
# readable for whatever PUID the container is told to run as
RUN chmod -R a+rX /srv && chmod +x /usr/local/bin/docker-entrypoint.sh && mkdir -p /data

EXPOSE 8080
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4).status==200 else 1)"

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
# --forwarded-allow-ips is appended by the entrypoint from CF0T_TRUSTED_PROXIES
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers"]
