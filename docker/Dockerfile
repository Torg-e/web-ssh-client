FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/*

RUN adduser --disabled-password --gecos "" --uid 1000 teashell-user

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chown -R teashell-user:teashell-user /app

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER teashell-user

ENTRYPOINT ["/entrypoint.sh"]
