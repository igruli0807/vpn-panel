# Test-only SSTP client (sstpc + pppd) for tests/test-vpnctl.sh.
FROM debian:12-slim
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends sstp-client ppp iproute2 iputils-ping ca-certificates >/dev/null \
 && rm -rf /var/lib/apt/lists/*
