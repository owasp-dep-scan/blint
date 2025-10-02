ARG SYSBASE=quay.io/almalinuxautobot/almalinux:10
FROM ${SYSBASE} AS system-build

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

RUN mkdir -p /mnt/sys-root; \
    dnf install --installroot /mnt/sys-root glibc-minimal-langpack microdnf java-21-openjdk-headless findutils which tar gzip zip unzip sudo nodejs nodejs-devel \
    bzip2 python3 python3-devel python3-pip \
    --releasever 10 --setopt install_weak_deps=false --nodocs -y; \
    dnf --installroot /mnt/sys-root clean all;
RUN rm -rf /mnt/sys-root/var/cache/dnf /mnt/sys-root/var/log/dnf* /mnt/sys-root/var/lib/dnf /mnt/sys-root/var/log/yum.*; \
    /bin/date +%Y%m%d_%H%M > /mnt/sys-root/etc/BUILDTIME ;  \
    echo '%_install_langs C.utf8' > /mnt/sys-root/etc/rpm/macros.image-language-conf; \
    echo 'LANG="C.utf8"' >  /mnt/sys-root/etc/locale.conf; \
    echo 'container' > /mnt/sys-root/etc/dnf/vars/infra; \
    rm -f /mnt/sys-root/etc/machine-id; \
    touch /mnt/sys-root/etc/machine-id; \
    touch /mnt/sys-root/etc/resolv.conf; \
    touch /mnt/sys-root/etc/hostname; \
    touch /mnt/sys-root/etc/.pwd.lock; \
    chmod 600 /mnt/sys-root/etc/.pwd.lock; \
    rm -rf /mnt/sys-root/usr/share/locale/en* /mnt/sys-root/boot /mnt/sys-root/dev/null /mnt/sys-root/var/log/hawkey.log ; \
    echo '0.0 0 0.0' > /mnt/sys-root/etc/adjtime; \
    echo '0' >> /mnt/sys-root/etc/adjtime; \
    echo 'UTC' >> /mnt/sys-root/etc/adjtime; \
    mkdir -p /mnt/sys-root/run/lock; \
    cd /mnt/sys-root/etc ; \
    ln -s ../usr/share/zoneinfo/UTC localtime

FROM scratch

COPY --link --from=system-build /mnt/sys-root/ /

ENV ANDROID_HOME=/opt/android-sdk-linux \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING="utf-8" \
    NYXSTONE_LLVM_PREFIX="/usr/lib64/llvm18"
ENV PATH=${PATH}:/usr/local/bin/:/root/.local/bin:${ANDROID_HOME}/cmdline-tools/latest/bin:${ANDROID_HOME}/tools:${ANDROID_HOME}/tools/bin:${ANDROID_HOME}/platform-tools:

RUN microdnf install -y make gcc g++ ncurses \
    && alternatives --install /usr/bin/python3 python /usr/bin/python3.12 1 \
    && python3 --version \
    && python3 -m pip install --upgrade pip \
    && python3 -m pip install setuptools --upgrade \
    && python3 -m pip install poetry \
    && microdnf install -y epel-release \
    && microdnf install -y --enablerepo=epel llvm18 llvm18-devel \
    && mkdir -p ${ANDROID_HOME}/cmdline-tools \
    && curl -L https://dl.google.com/android/repository/commandlinetools-linux-13114758_latest.zip -o ${ANDROID_HOME}/cmdline-tools/android_tools.zip \
    && unzip ${ANDROID_HOME}/cmdline-tools/android_tools.zip -d ${ANDROID_HOME}/cmdline-tools/ \
    && rm ${ANDROID_HOME}/cmdline-tools/android_tools.zip \
    && mv ${ANDROID_HOME}/cmdline-tools/cmdline-tools ${ANDROID_HOME}/cmdline-tools/latest \
    && yes | /opt/android-sdk-linux/cmdline-tools/latest/bin/sdkmanager --licenses --sdk_root=/opt/android-sdk-linux \
    && /opt/android-sdk-linux/cmdline-tools/latest/bin/sdkmanager 'platform-tools' --sdk_root=/opt/android-sdk-linux \
    && /opt/android-sdk-linux/cmdline-tools/latest/bin/sdkmanager 'platforms;android-36' --sdk_root=/opt/android-sdk-linux \
    && /opt/android-sdk-linux/cmdline-tools/latest/bin/sdkmanager 'build-tools;36.0.0' --sdk_root=/opt/android-sdk-linux
COPY . /opt/blint
RUN cd /opt/blint \
    && poetry config virtualenvs.create false \
    && poetry install --no-cache --all-groups --all-extras \
    && chmod a-w -R /opt \
    && microdnf clean all

ENTRYPOINT [ "blint" ]
