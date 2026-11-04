#!/bin/sh
# Generate a self-signed cert and an nginx TLS vhost. MODE=good|bad decides how
# weak the settings are. Certs are generated at runtime so no private key is
# ever committed to the repo.
set -e

cn="${CN:-tls.lab}"
mode="${MODE:-good}"
d=/etc/nginx/tls
mkdir -p "$d"

# nginx:alpine ships without the openssl CLI; add it at runtime.
command -v openssl >/dev/null 2>&1 || apk add --no-cache openssl >/dev/null 2>&1

if [ "$mode" = "bad" ]; then
    # WEAK: 1024-bit RSA, only 3 days validity (near expiry), permissive ciphers.
    openssl req -x509 -newkey rsa:1024 -sha256 -nodes -days 3 \
        -keyout "$d/server.key" -out "$d/server.crt" \
        -subj "/CN=$cn" -addext "subjectAltName=DNS:$cn" 2>/dev/null
    protocols="TLSv1.2"
    ciphers="DEFAULT:@SECLEVEL=0"
else
    # GOOD: 2048-bit RSA, 825-day validity, modern protocols and ciphers.
    openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 825 \
        -keyout "$d/server.key" -out "$d/server.crt" \
        -subj "/CN=$cn" -addext "subjectAltName=DNS:$cn" 2>/dev/null
    protocols="TLSv1.2 TLSv1.3"
    ciphers="HIGH:!aNULL:!MD5"
fi

cat > /etc/nginx/conf.d/default.conf <<EOF
server {
    listen 443 ssl;
    server_name $cn;
    ssl_certificate     $d/server.crt;
    ssl_certificate_key $d/server.key;
    ssl_protocols $protocols;
    ssl_ciphers $ciphers;
    location / { return 200 "$mode TLS lab target ($cn)\n"; }
}
EOF

exec nginx -g 'daemon off;'
