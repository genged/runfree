# syntax=docker/dockerfile:1.7
#
# Agent agent image for the extracted Runfree runtime.

ARG RUNFREE_UV_IMAGE
ARG RUNFREE_AGENT_BASE_IMAGE

FROM ${RUNFREE_UV_IMAGE} AS uv
FROM ${RUNFREE_AGENT_BASE_IMAGE}

ARG RUNFREE_APT_SOURCE_UBUNTU_URL
ARG RUNFREE_APT_SOURCE_UBUNTU_SUITES
ARG RUNFREE_APT_SOURCE_UBUNTU_COMPONENTS
ARG RUNFREE_APT_SOURCE_UBUNTU_SECURITY_URL
ARG RUNFREE_APT_SOURCE_UBUNTU_SECURITY_SUITES
ARG RUNFREE_APT_SOURCE_UBUNTU_SECURITY_COMPONENTS
ARG RUNFREE_APT_SIGNED_BY
ARG RUNFREE_APT_PACKAGE_CA_CERTIFICATES
ARG RUNFREE_APT_PACKAGE_CURL
ARG RUNFREE_APT_PACKAGE_SUDO
ARG RUNFREE_APT_PACKAGE_GIT
ARG RUNFREE_APT_PACKAGE_JQ
ARG RUNFREE_APT_PACKAGE_RIPGREP
ARG RUNFREE_APT_PACKAGE_ZSH
ARG RUNFREE_APT_PACKAGE_IPROUTE2
ARG RUNFREE_APT_PACKAGE_NETCAT_OPENBSD
ARG RUNFREE_APT_PACKAGE_BIND9_DNSUTILS
ARG RUNFREE_APT_PACKAGE_NODEJS
ARG RUNFREE_APT_PACKAGE_NPM
ARG RUNFREE_GH_VERSION
ARG RUNFREE_GH_LINUX_AMD64_DEB_URL
ARG RUNFREE_GH_LINUX_AMD64_DEB_SHA256
ARG RUNFREE_GH_LINUX_ARM64_DEB_URL
ARG RUNFREE_GH_LINUX_ARM64_DEB_SHA256
ARG RUNFREE_PNPM_VERSION

COPY --from=uv /uv /uvx /usr/local/bin/

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

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
      "$RUNFREE_APT_PACKAGE_CURL" \
      "$RUNFREE_APT_PACKAGE_SUDO" \
      "$RUNFREE_APT_PACKAGE_GIT" \
      "$RUNFREE_APT_PACKAGE_JQ" \
      "$RUNFREE_APT_PACKAGE_RIPGREP" \
      "$RUNFREE_APT_PACKAGE_ZSH" \
      "$RUNFREE_APT_PACKAGE_IPROUTE2" \
      "$RUNFREE_APT_PACKAGE_NETCAT_OPENBSD" \
      "$RUNFREE_APT_PACKAGE_BIND9_DNSUTILS" \
      "$RUNFREE_APT_PACKAGE_NODEJS" \
      "$RUNFREE_APT_PACKAGE_NPM" \
      "$RUNFREE_GH_VERSION" \
      "$RUNFREE_GH_LINUX_AMD64_DEB_URL" \
      "$RUNFREE_GH_LINUX_AMD64_DEB_SHA256" \
      "$RUNFREE_GH_LINUX_ARM64_DEB_URL" \
      "$RUNFREE_GH_LINUX_ARM64_DEB_SHA256" \
      "$RUNFREE_PNPM_VERSION"; do \
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
      "curl=${RUNFREE_APT_PACKAGE_CURL}" \
      "sudo=${RUNFREE_APT_PACKAGE_SUDO}" \
      "git=${RUNFREE_APT_PACKAGE_GIT}" \
      "jq=${RUNFREE_APT_PACKAGE_JQ}" \
      "ripgrep=${RUNFREE_APT_PACKAGE_RIPGREP}" \
      "zsh=${RUNFREE_APT_PACKAGE_ZSH}" \
      "iproute2=${RUNFREE_APT_PACKAGE_IPROUTE2}" \
      "netcat-openbsd=${RUNFREE_APT_PACKAGE_NETCAT_OPENBSD}" \
      "bind9-dnsutils=${RUNFREE_APT_PACKAGE_BIND9_DNSUTILS}" \
      "nodejs=${RUNFREE_APT_PACKAGE_NODEJS}" \
      "npm=${RUNFREE_APT_PACKAGE_NPM}" \
 && git_version="${RUNFREE_APT_PACKAGE_GIT#*:}" \
 && git_version="${git_version%%-*}" \
 && git --version | grep -F "git version ${git_version}" >/dev/null \
 && tmp_git_probe="$(mktemp -d)" \
 && git -C "$tmp_git_probe" init -q \
 && if git -C "$tmp_git_probe" worktree repair -h > /tmp/git-worktree-help.txt 2>&1; then help_status=0; else help_status="$?"; fi \
 && case "$help_status" in 0|129) ;; *) exit "$help_status" ;; esac \
 && grep -F "relative-paths" /tmp/git-worktree-help.txt >/dev/null \
 && rm -f /tmp/git-worktree-help.txt \
 && rm -rf "$tmp_git_probe" \
 && rm -rf /var/lib/apt/lists/*

RUN set -eu \
 && arch="$(dpkg --print-architecture)" \
 && case "$arch" in \
      amd64) gh_url="$RUNFREE_GH_LINUX_AMD64_DEB_URL"; gh_sha="$RUNFREE_GH_LINUX_AMD64_DEB_SHA256" ;; \
      arm64) gh_url="$RUNFREE_GH_LINUX_ARM64_DEB_URL"; gh_sha="$RUNFREE_GH_LINUX_ARM64_DEB_SHA256" ;; \
      *) echo "unsupported GitHub CLI architecture: $arch" >&2; exit 1 ;; \
    esac \
 && curl -fsSLo /tmp/gh.deb "$gh_url" \
 && printf '%s  /tmp/gh.deb\n' "$gh_sha" | sha256sum -c - \
 && apt-get update \
 && apt-get install -y --no-install-recommends /tmp/gh.deb \
 && rm -f /tmp/gh.deb \
 && rm -rf /var/lib/apt/lists/* \
 && gh --version | grep -F "gh version $RUNFREE_GH_VERSION" >/dev/null

COPY agent-tools/package.json agent-tools/package-lock.json /opt/runfree-agent-tools/
RUN node -e 'const [major, minor] = process.versions.node.split(".").map(Number); if (major < 22 || (major === 22 && minor < 19)) { console.error("Pi requires Node >=22.19.0"); process.exit(1); }'
RUN npm ci --prefix /opt/runfree-agent-tools --omit=dev --ignore-scripts \
 && node -e 'const pkg = require("/opt/runfree-agent-tools/node_modules/pnpm/package.json"); if (pkg.version !== process.env.RUNFREE_PNPM_VERSION) { console.error(`pnpm lock mismatch: ${pkg.version} !== ${process.env.RUNFREE_PNPM_VERSION}`); process.exit(1); }' \
 && npm cache clean --force
RUN --network=none npm rebuild --prefix /opt/runfree-agent-tools --omit=dev
COPY claude-runfree.sh /usr/local/libexec/runfree/claude
# The session container's first process: waits for the proxy to report the
# session active, then execs the typed agent argv. Cooperation, not
# enforcement; see docs/security.md "Per-Session Admission".
COPY session-entry.sh /usr/local/libexec/runfree/session-entry
COPY session-ready-probe.cjs /usr/local/libexec/runfree/session-ready-probe
RUN chmod 0755 /usr/local/libexec/runfree/claude \
      /usr/local/libexec/runfree/session-entry \
      /usr/local/libexec/runfree/session-ready-probe \
 && ln -s /opt/runfree-agent-tools/node_modules/.bin/claude /usr/local/libexec/runfree/claude-real \
 && ln -s /usr/local/libexec/runfree/claude /usr/local/bin/claude \
 && ln -s /opt/runfree-agent-tools/node_modules/.bin/codex /usr/local/bin/codex \
 && ln -s /opt/runfree-agent-tools/node_modules/.bin/pi /usr/local/bin/pi \
 && ln -s /opt/runfree-agent-tools/node_modules/.bin/pnpm /usr/local/bin/pnpm \
 && ln -s /opt/runfree-agent-tools/node_modules/.bin/tsx /usr/local/bin/tsx

ARG USERNAME=agent
ARG UID=1000
ARG GID=1000

RUN set -eu \
 && existing_user="$(getent passwd "${UID}" | cut -d: -f1 || true)" \
 && if [ -n "$existing_user" ] && [ "$existing_user" != "$USERNAME" ]; then userdel -r "$existing_user" 2>/dev/null || userdel "$existing_user"; fi \
 && existing_group="$(getent group "${GID}" | cut -d: -f1 || true)" \
 && if [ -n "$existing_group" ] && [ "$existing_group" != "$USERNAME" ]; then groupmod --new-name "$USERNAME" "$existing_group"; fi \
 && if ! getent group "$USERNAME" >/dev/null; then groupadd --gid "${GID}" "$USERNAME"; fi \
 && groupmod --gid "${GID}" "$USERNAME" \
 && if getent passwd "$USERNAME" >/dev/null; then usermod --uid "${UID}" --gid "${GID}" --home "/home/${USERNAME}" --shell /usr/bin/zsh "$USERNAME"; else useradd --uid "${UID}" --gid "${GID}" --create-home --shell /usr/bin/zsh "$USERNAME"; fi \
 && mkdir -p "/home/${USERNAME}" \
 && chown "${USERNAME}:${USERNAME}" "/home/${USERNAME}" \
 && install -d -m 0755 -o "${USERNAME}" -g "${USERNAME}" \
      "/home/${USERNAME}/.local" \
      "/home/${USERNAME}/.local/bin"

RUN printf 'export PATH=$PATH:/home/%s/.local/bin\nautoload -Uz compinit && compinit\n' "${USERNAME}" \
      > "/home/${USERNAME}/.zshrc" \
 && chown "${USERNAME}:${USERNAME}" "/home/${USERNAME}/.zshrc"
RUN mkdir -p /workspaces \
 && chown "${USERNAME}:${USERNAME}" /workspaces

USER ${USERNAME}
WORKDIR /workspace

CMD ["sleep", "infinity"]
