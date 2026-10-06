FROM python:3.11-slim

WORKDIR /srv

# Application is pure standard library; no runtime dependencies.
COPY app ./app

ENV ARBITER_HOST=0.0.0.0 \
    ARBITER_PORT=8080 \
    ARBITER_STORE=/data/sealed.json

EXPOSE 8080

VOLUME ["/data"]

HEALTHCHECK --interval=5s --timeout=3s --start-period=2s --retries=5 \
    CMD python3 -c "import json,urllib.request,sys; \
r=urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=3); \
sys.exit(0 if json.load(r)['status']=='ok' else 1)"

CMD ["python3", "-m", "app.service"]
