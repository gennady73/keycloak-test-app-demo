# Local Keycloak (upstream) for developing/testing the Phase 0 tool.
# Upstream Keycloak 26.6.4-1, NOT RHBK: behaviour matches closely, but patch numbers differ
# from RHBK (RHBK 26.6.6 != upstream 26.6.6). Pick the tag you want via --build-arg.
ARG KEYCLOAK_VERSION=26.6.4-1
# Registry/repo you verified: Docker Hub keycloak/keycloak:26.6.4-1 (quay.io/keycloak/keycloak also works if it carries the tag)
ARG KEYCLOAK_IMAGE=docker.io/keycloak/keycloak

# ---- stage 1: build the optimized server (build-time options are baked in here) ----
FROM ${KEYCLOAK_IMAGE}:${KEYCLOAK_VERSION} AS builder
ENV KC_HEALTH_ENABLED=true \
    KC_METRICS_ENABLED=false \
    KC_DB=dev-file
RUN /opt/keycloak/bin/kc.sh build

# ---- stage 2: runtime image ----
FROM ${KEYCLOAK_IMAGE}:${KEYCLOAK_VERSION}
COPY --from=builder /opt/keycloak/ /opt/keycloak/

# Runtime options. Override with `docker run -e ...`.
# Hostname is deliberately explicit: it is exactly what the issuer/hostname incident is about.
ENV KC_HTTP_ENABLED=true \
    KC_HOSTNAME=http://localhost:8080 \
    KC_HOSTNAME_STRICT=true
# Admin bootstrap user (26.x variable names). Change the password; never reuse it elsewhere.
ENV KC_BOOTSTRAP_ADMIN_USERNAME=admin \
    KC_BOOTSTRAP_ADMIN_PASSWORD=change-me-please

# 8080 = application, 9000 = management interface (/health/ready)
EXPOSE 8080 9000
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--optimized"]
