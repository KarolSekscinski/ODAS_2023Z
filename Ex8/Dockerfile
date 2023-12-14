
FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y nginx openssl && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/nginx/ssl

RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/nginx/ssl/nginx.key -out /etc/nginx/ssl/nginx.crt -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

COPY nginx.conf /etc/nginx/sites-available/default

EXPOSE 8080
EXPOSE 443

CMD ["nginx", "-g", "daemon off;"]
