FROM ghcr.io/appthreat/base-lang:main

LABEL maintainer="appthreat" \
      org.opencontainers.image.authors="Team AppThreat <cloud@appthreat.com>" \
      org.opencontainers.image.source="https://github.com/owasp-dep-scan/blint" \
      org.opencontainers.image.url="https://github.com/owasp-dep-scan/blint" \
      org.opencontainers.image.version="2.4.x" \
      org.opencontainers.image.vendor="OWASP" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.title="blint" \
      org.opencontainers.image.description="BLint is a Binary Linter and SBOM generator." \
      org.opencontainers.docker.cmd="docker run --rm -it -v /tmp:/tmp -v $(pwd):/app:rw -w /app -t ghcr.io/owasp-dep-scan/blint"

ENV ANDROID_HOME=/opt/android-sdk-linux \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING="utf-8"
ENV PATH=${PATH}:/usr/local/bin/:/root/.local/bin:${ANDROID_HOME}/cmdline-tools/latest/bin:${ANDROID_HOME}/tools:${ANDROID_HOME}/tools/bin:${ANDROID_HOME}/platform-tools:

RUN microdnf install -y make gcc ncurses \
    && alternatives --install /usr/bin/python3 python /usr/bin/python3.12 1 \
    && python3 --version \
    && python3 -m pip install --upgrade pip \
    && python3 -m pip install setuptools --upgrade \
    && python3 -m pip install poetry \
    && microdnf install -y epel-release \
    && mkdir -p ${ANDROID_HOME}/cmdline-tools \
    && curl -L https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip -o ${ANDROID_HOME}/cmdline-tools/android_tools.zip \
    && unzip ${ANDROID_HOME}/cmdline-tools/android_tools.zip -d ${ANDROID_HOME}/cmdline-tools/ \
    && rm ${ANDROID_HOME}/cmdline-tools/android_tools.zip \
    && mv ${ANDROID_HOME}/cmdline-tools/cmdline-tools ${ANDROID_HOME}/cmdline-tools/latest \
    && yes | /opt/android-sdk-linux/cmdline-tools/latest/bin/sdkmanager --licenses --sdk_root=/opt/android-sdk-linux \
    && /opt/android-sdk-linux/cmdline-tools/latest/bin/sdkmanager 'platform-tools' --sdk_root=/opt/android-sdk-linux \
    && /opt/android-sdk-linux/cmdline-tools/latest/bin/sdkmanager 'platforms;android-34' --sdk_root=/opt/android-sdk-linux \
    && /opt/android-sdk-linux/cmdline-tools/latest/bin/sdkmanager 'build-tools;34.0.0' --sdk_root=/opt/android-sdk-linux
COPY . /opt/blint
RUN cd /opt/blint \
    && poetry config virtualenvs.create false \
    && poetry install --no-cache --without dev \
    && chmod a-w -R /opt \
    && microdnf remove make gcc -y \
    && microdnf clean all

ENTRYPOINT [ "blint" ]
