# AmneziaWG 3.1 server image (userspace amneziawg-go; kernel module needs Linux >= 6.7).
# Versions are pinned by tag; bump both together and rebuild.
ARG AWG_GO_REF=v3.1.20260828
ARG AWG_TOOLS_REF=v3.1.20260812

FROM golang:1.25-alpine AS go
ARG AWG_GO_REF
RUN apk add --no-cache git
RUN git clone --depth 1 --branch "${AWG_GO_REF}" https://github.com/amnezia-vpn/amneziawg-go /src
WORKDIR /src
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/amneziawg-go .

FROM alpine:3.20 AS tools
ARG AWG_TOOLS_REF
RUN apk add --no-cache git build-base linux-headers
RUN git clone --depth 1 --branch "${AWG_TOOLS_REF}" https://github.com/amnezia-vpn/amneziawg-tools /src \
 && make -C /src/src

FROM alpine:3.20
ARG AWG_GO_REF
ARG AWG_TOOLS_REF
LABEL org.opencontainers.image.title="awg3" \
      org.opencontainers.image.description="AmneziaWG 3.1 server (amneziawg-go ${AWG_GO_REF}, tools ${AWG_TOOLS_REF})"
RUN apk add --no-cache bash iproute2 iptables
COPY --from=tools /src/src/wg /usr/bin/awg
COPY --from=tools /src/src/wg-quick/linux.bash /usr/bin/awg-quick
COPY --from=go /out/amneziawg-go /usr/bin/amneziawg-go
COPY start.sh /usr/local/bin/start.sh
RUN chmod 755 /usr/bin/awg /usr/bin/awg-quick /usr/local/bin/start.sh \
 && ln -s awg /usr/bin/wg && ln -s awg-quick /usr/bin/wg-quick
ENV WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go \
    AWG_IF=awg0 \
    AWG_DIR=/etc/awg
VOLUME /etc/awg
ENTRYPOINT ["/usr/local/bin/start.sh"]
