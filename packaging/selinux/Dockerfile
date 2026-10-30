# SPDX-License-Identifier: AGPL-3.0-only
# Build only in a disposable linux/amd64 container. No policy is loaded.
FROM rockylinux/rockylinux:8@sha256:e8a49c5403b687db05d4d67333fa45808fbe74f36e683cec7abb1f7d0f2338c6
# The immutable base supplies the Rocky 8 release key and RPM/DNF bootstrap.
# Verify the key bytes before importing; dependency RPM signatures are mandatory.
RUN set -eu; \
    key=/etc/pki/rpm-gpg/RPM-GPG-KEY-rockyofficial; \
    echo "ef1ca99bba38bb2869a06fbf46860fcdaeece796be98f8dfb0160b84bdbc69ab  $key" | sha256sum -c -; \
    rpm --import "$key"; \
    mkdir -p /build/keyring; \
    rpm --dbpath /build/keyring --initdb; \
    rpm --dbpath /build/keyring --import "$key"; \
    timeout 600 dnf -y --disablerepo='*' \
      --repofrompath=policy-base,https://dl.rockylinux.org/pub/rocky/8.10/BaseOS/x86_64/os/ \
      --repofrompath=policy-app,https://dl.rockylinux.org/pub/rocky/8.10/AppStream/x86_64/os/ \
      --setopt=gpgcheck=1 --setopt=localpkg_gpgcheck=1 \
      --setopt=policy-base.gpgkey="file://$key" \
      --setopt=policy-app.gpgkey="file://$key" \
      --setopt=timeout=30 --setopt=retries=2 --setopt=install_weak_deps=False \
      install checkpolicy-2.9-1.el8.x86_64 gawk-4.2.1-4.el8.x86_64 \
      libsepol-2.9-3.el8.x86_64 m4-1.4.18-7.el8.x86_64 \
      make-4.2.1-11.el8.x86_64 policycoreutils-devel-2.9-26.el8_10.x86_64 \
      cpio findutils platform-python; \
    dnf clean all
WORKDIR /src
