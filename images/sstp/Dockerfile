# SSTP server image: accel-ppp built from source (no kernel modules, no RADIUS).
# Config, chap-secrets and the certificate live in the /etc/accel-ppp volume (written by vpnctl install sstp).
ARG ACCEL_REF=1.14.0

FROM debian:12-slim AS build
ARG ACCEL_REF
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
      git ca-certificates build-essential cmake libssl-dev libpcre2-dev libpcre3-dev >/dev/null
RUN git clone --depth 1 --branch "${ACCEL_REF}" https://github.com/accel-ppp/accel-ppp.git /src
WORKDIR /src/build
RUN cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release -DCRYPTO=OPENSSL \
      -DBUILD_IPOE_DRIVER=FALSE -DBUILD_VLAN_MON_DRIVER=FALSE -DRADIUS=FALSE -DSHAPER=FALSE \
      -DLUA=FALSE -DNETSNMP=FALSE -DLOG_PGSQL=FALSE .. >/dev/null \
 && make -j"$(nproc)" >/dev/null && make install DESTDIR=/out >/dev/null

FROM debian:12-slim
ARG ACCEL_REF
LABEL org.opencontainers.image.title="sstp" \
      org.opencontainers.image.description="SSTP server (accel-ppp ${ACCEL_REF})"
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
      libssl3 libpcre2-8-0 libpcre3 iptables iproute2 openssl procps >/dev/null \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/usr/ /usr/
COPY start.sh /usr/local/bin/start.sh
RUN chmod 755 /usr/local/bin/start.sh && ldconfig && accel-pppd --version >/dev/null 2>&1 || true
VOLUME /etc/accel-ppp
ENTRYPOINT ["/usr/local/bin/start.sh"]
