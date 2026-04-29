FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/*

RUN adduser --disabled-password --gecos "" --uid 1000 teashell-user

WORKDIR /app

COPY src/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
ENV PYTHONPATH=/app/src

RUN chown -R root:root /app && chmod -R 755 /app
RUN mkdir -p /app/data && chown teashell-user:teashell-user /app/data && chmod 700 /app/data

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER teashell-user

ENTRYPOINT ["/entrypoint.sh"]
