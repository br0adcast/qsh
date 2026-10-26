# A disposable host for perf_baseline.py's system-mode variants. Build it
# with the PAM service files as the context:
#
#   docker build -f scripts/perf_baseline_system.Dockerfile -t qsh-bench-system packaging/pam.d
#
# Never run those variants anywhere else: they run qshd as root and write the
# benchmark account's authorized_keys. See docs/performance-baseline.md.
FROM ubuntu:24.04
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 openssh-client libpam-modules \
 && rm -rf /var/lib/apt/lists/*
# The account sessions log in as, with present, empty shell startup files.
RUN useradd --create-home --shell /bin/sh qshbench \
 && cd /home/qshbench \
 && for f in .profile .bashrc .bash_profile .zshrc; do : > "$f"; done \
 && printf 'unsetopt GLOBAL_RCS\n' > .zshenv \
 && install -d -m 700 -o qshbench -g qshbench .ssh \
 && chown qshbench:qshbench .profile .bashrc .bash_profile .zshrc .zshenv
COPY qshd.debian /etc/pam.d/qshd
