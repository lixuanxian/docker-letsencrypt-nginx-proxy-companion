# syntax=docker/dockerfile:1
FROM docker.io/nginxproxy/docker-gen:0.17.2 AS docker-gen

FROM docker.io/library/alpine:3.24.1

ARG GIT_DESCRIBE="unknown"
ARG ACMESH_VERSION=3.1.4

ENV ACMESH_VERSION=${ACMESH_VERSION} \
    COMPANION_VERSION=${GIT_DESCRIBE} \
    DOCKER_HOST=unix:///var/run/docker.sock \
    PATH=${PATH}:/app

# Install packages required by the image
RUN apk add --no-cache --virtual .bin-deps \
    bash \
    bind-tools \
    coreutils \
    curl \
    jq \
    libidn \
    oath-toolkit-oathtool \
    openssh-client \
    openssl \
    sed \
    socat \
    tar \
    tzdata

# Install docker-gen from the nginxproxy/docker-gen image
COPY --from=docker-gen /usr/local/bin/docker-gen /usr/local/bin/

# Install acme.sh
COPY /install_acme.sh /app/install_acme.sh

# Normalize potential CRLF line endings (e.g. from a Windows checkout) to LF
# before executing, otherwise the shebang breaks with "/bin/bash: not found".
RUN sed -i 's/\r$//' /app/install_acme.sh \
    && chmod +rx /app/install_acme.sh \
    && sync \
    && /app/install_acme.sh \
    && rm -f /app/install_acme.sh

COPY app LICENSE /app/

# Normalize line endings for all app scripts and assets so that images
# built on Windows (CRLF working tree) still run correctly. Recurses into
# subdirectories and skips directories; a no-op for LF checkouts.
# See .gitattributes for repo-level enforcement.
RUN find /app -type f -exec sed -i 's/\r$//' {} +

# Create symlinks for scripts in /app to /usr/local/bin
RUN /app/install_scripts.sh

WORKDIR /app

ENTRYPOINT [ "/bin/bash", "/app/entrypoint.sh" ]
CMD [ "/bin/bash", "/app/start.sh" ]
