FROM almalinux:9.2-minimal

LABEL maintainer="appthreat" \
      org.opencontainers.image.authors="Team AppThreat <cloud@appthreat.com>" \
      org.opencontainers.image.source="https://github.com/AppThreat/blint" \
      org.opencontainers.image.url="https://github.com/AppThreat/blint" \
      org.opencontainers.image.version="1.0.31" \
      org.opencontainers.image.vendor="AppThreat" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.title="blint" \
      org.opencontainers.image.description="BLint is a Binary Linter to check the security properties, and capabilities in your executables. It is powered by lief." \
      org.opencontainers.docker.cmd="docker run --rm -it -v /tmp:/tmp -v $(pwd):/app:rw -w /app -t ghcr.io/appthreat/blint"

ARG TARGETPLATFORM
ARG JAVA_VERSION=22.3.r19-grl
ARG SBT_VERSION=1.9.0
ARG MAVEN_VERSION=3.9.2
ARG GRADLE_VERSION=8.1.1

ENV GOPATH=/opt/app-root/go \
    GO_VERSION=1.20.4 \
    JAVA_VERSION=$JAVA_VERSION \
    SBT_VERSION=$SBT_VERSION \
    MAVEN_VERSION=$MAVEN_VERSION \
    GRADLE_VERSION=$GRADLE_VERSION \
    GRADLE_OPTS="-Dorg.gradle.daemon=false" \
    JAVA_HOME="/opt/java/${JAVA_VERSION}" \
    MAVEN_HOME="/opt/maven/${MAVEN_VERSION}" \
    GRADLE_HOME="/opt/gradle/${GRADLE_VERSION}" \
    SBT_HOME="/opt/sbt/${SBT_VERSION}" \
    COMPOSER_ALLOW_SUPERUSER=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING="utf-8"
ENV PATH=${PATH}:${JAVA_HOME}/bin:${MAVEN_HOME}/bin:${GRADLE_HOME}/bin:${SBT_HOME}/bin:${GOPATH}/bin:/usr/local/go/bin:/usr/local/bin/:/root/.local/bin:

COPY . /opt/blint

RUN microdnf install -y python3.11 python3.11-pip cmake gcc glibc-common \
    && alternatives --install /usr/bin/python3 python /usr/bin/python3.11 1 \
    && python3 --version \
    && python3 -m pip install --upgrade pip \
    && cd /opt/blint \
    && python3 -m pip install -e . \
    && chmod a-w -R /opt \
    && microdnf clean all


WORKDIR /app

ENTRYPOINT [ "blint" ]
