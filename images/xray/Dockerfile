# VLESS (Xray REALITY) server image: official xray binary on alpine (the official image has no shell,
# and vpnctl manages users through `docker exec ... xray api`).
ARG XRAY_REF=26.3.27
FROM ghcr.io/xtls/xray-core:${XRAY_REF} AS xray

FROM alpine:3.20
ARG XRAY_REF
LABEL org.opencontainers.image.title="xray" \
      org.opencontainers.image.description="VLESS REALITY server (Xray ${XRAY_REF})"
RUN apk add --no-cache ca-certificates tzdata
COPY --from=xray /usr/local/bin/xray /usr/local/bin/xray
VOLUME /etc/xray
ENTRYPOINT ["/usr/local/bin/xray", "run", "-config", "/etc/xray/config.json"]
