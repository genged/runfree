# syntax=docker/dockerfile:1.7
#
# Credential-injection proxy for the extracted Runfree runtime.

ARG RUNFREE_PROXY_BASE_IMAGE
FROM ${RUNFREE_PROXY_BASE_IMAGE}

ARG RUNFREE_APT_SOURCE_UBUNTU_URL
ARG RUNFREE_APT_SOURCE_UBUNTU_SUITES
ARG RUNFREE_APT_SOURCE_UBUNTU_COMPONENTS
ARG RUNFREE_APT_SOURCE_UBUNTU_SECURITY_URL
ARG RUNFREE_APT_SOURCE_UBUNTU_SECURITY_SUITES
ARG RUNFREE_APT_SOURCE_UBUNTU_SECURITY_COMPONENTS
ARG RUNFREE_APT_SIGNED_BY
ARG RUNFREE_APT_PACKAGE_CA_CERTIFICATES
ARG RUNFREE_APT_PACKAGE_DUMB_INIT
ARG RUNFREE_APT_PACKAGE_IPROUTE2
ARG RUNFREE_APT_PACKAGE_NFTABLES
ARG RUNFREE_APT_PACKAGE_BIND9_DNSUTILS
ARG RUNFREE_APT_PACKAGE_BASH
ARG RUNFREE_APT_PACKAGE_UTIL_LINUX
ARG RUNFREE_APT_PACKAGE_NODEJS
ARG RUNFREE_APT_PACKAGE_NPM

ENV DEBIAN_FRONTEND=noninteractive

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN set -eu \
 && for value in \
      "$RUNFREE_APT_SOURCE_UBUNTU_URL" \
      "$RUNFREE_APT_SOURCE_UBUNTU_SUITES" \
      "$RUNFREE_APT_SOURCE_UBUNTU_COMPONENTS" \
      "$RUNFREE_APT_SOURCE_UBUNTU_SECURITY_URL" \
      "$RUNFREE_APT_SOURCE_UBUNTU_SECURITY_SUITES" \
      "$RUNFREE_APT_SOURCE_UBUNTU_SECURITY_COMPONENTS" \
      "$RUNFREE_APT_SIGNED_BY" \
      "$RUNFREE_APT_PACKAGE_CA_CERTIFICATES" \
      "$RUNFREE_APT_PACKAGE_DUMB_INIT" \
      "$RUNFREE_APT_PACKAGE_IPROUTE2" \
      "$RUNFREE_APT_PACKAGE_NFTABLES" \
      "$RUNFREE_APT_PACKAGE_BIND9_DNSUTILS" \
      "$RUNFREE_APT_PACKAGE_BASH" \
      "$RUNFREE_APT_PACKAGE_UTIL_LINUX" \
      "$RUNFREE_APT_PACKAGE_NODEJS" \
      "$RUNFREE_APT_PACKAGE_NPM"; do \
        test -n "$value"; \
    done

RUN set -eu \
 && rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources \
 && test -f "$RUNFREE_APT_SIGNED_BY" \
 && { \
      printf 'Types: deb\nURIs: %s\nSuites: %s\nComponents: %s\nSigned-By: %s\n\n' \
        "$RUNFREE_APT_SOURCE_UBUNTU_URL" \
        "$RUNFREE_APT_SOURCE_UBUNTU_SUITES" \
        "$RUNFREE_APT_SOURCE_UBUNTU_COMPONENTS" \
        "$RUNFREE_APT_SIGNED_BY"; \
      printf 'Types: deb\nURIs: %s\nSuites: %s\nComponents: %s\nSigned-By: %s\n' \
        "$RUNFREE_APT_SOURCE_UBUNTU_SECURITY_URL" \
        "$RUNFREE_APT_SOURCE_UBUNTU_SECURITY_SUITES" \
        "$RUNFREE_APT_SOURCE_UBUNTU_SECURITY_COMPONENTS" \
        "$RUNFREE_APT_SIGNED_BY"; \
    } > /etc/apt/sources.list.d/runfree.sources \
 && printf 'Acquire::Retries "3";\n' > /etc/apt/apt.conf.d/99runfree-apt \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      "ca-certificates=${RUNFREE_APT_PACKAGE_CA_CERTIFICATES}" \
      "dumb-init=${RUNFREE_APT_PACKAGE_DUMB_INIT}" \
      "iproute2=${RUNFREE_APT_PACKAGE_IPROUTE2}" \
      "nftables=${RUNFREE_APT_PACKAGE_NFTABLES}" \
      "bind9-dnsutils=${RUNFREE_APT_PACKAGE_BIND9_DNSUTILS}" \
      "bash=${RUNFREE_APT_PACKAGE_BASH}" \
      "util-linux=${RUNFREE_APT_PACKAGE_UTIL_LINUX}" \
      "nodejs=${RUNFREE_APT_PACKAGE_NODEJS}" \
      "npm=${RUNFREE_APT_PACKAGE_NPM}" \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 1001 --system runfree-proxy \
 && useradd --uid 1001 --gid runfree-proxy --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin runfree-proxy

WORKDIR /app/proxy

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts \
 && npm cache clean --force
RUN --network=none npm rebuild --omit=dev

COPY *.js ./
COPY firewall ./firewall
COPY contracts ./contracts

RUN mkdir -p /ca/private /ca/public \
 && chown -R runfree-proxy:runfree-proxy /ca

ENV PROXY_SECRET_DIR=/run/runfree-proxy-secrets \
    CA_CERT=/ca/public/proxy-ca.crt \
    CA_KEY=/ca/private/proxy-ca.key

EXPOSE 8080

ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "/app/proxy/entrypoint.js"]
