FROM nginx:1.25

RUN rm /etc/nginx/conf.d/default.conf
RUN mkdir -p /etc/nginx/ssl
COPY nginx.conf /etc/nginx/conf.d
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/nginx/ssl/localhost.key -out /etc/nginx/ssl/localhost.crt -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

