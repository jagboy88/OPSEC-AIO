# syntax=docker/dockerfile:1
# Tor onion service for OpSec AIO. Runs in Caddy's network namespace and
# forwards the onion's port 80 to Caddy's localhost-only onion site.
FROM alpine:3.24.4
RUN apk add --no-cache tor=0.4.9.17-r0 \
 && mkdir -p /var/lib/tor && chown tor:tor /var/lib/tor && chmod 700 /var/lib/tor
COPY infra/tor/torrc /etc/tor/torrc
USER tor
CMD ["tor", "-f", "/etc/tor/torrc"]
