# Explicit staged inputs are supplied by build-fedora-packages.sh.
%global debug_package %{nil}
%global __brp_python_bytecompile %{nil}
%global __os_install_post %{nil}
%global _unpackaged_files_terminate_build 1
Name: qshd-selinux
Version: %{qsh_version}
Release: %{qsh_release}
Summary: Fedora targeted SELinux pair for qshd system mode
License: AGPL-3.0-only AND GPL-2.0-or-later
BuildArch: noarch
AutoReqProv: no
Provides: qshd-selinux-abi = 2
Requires: python3 >= 3.10
Requires: libselinux, selinux-policy-targeted, policycoreutils
Requires: /usr/bin/python3, /usr/bin/semodule, /usr/bin/rpm, /usr/bin/systemctl
Requires(pre): python3, libselinux, selinux-policy-targeted, policycoreutils
Requires(pre): /usr/bin/python3, /usr/bin/semodule, /usr/bin/rpm, /usr/bin/systemctl
Requires(post): python3, libselinux, selinux-policy-targeted, policycoreutils
Requires(post): /usr/bin/python3, /usr/bin/semodule, /usr/bin/rpm, /usr/bin/systemctl
Requires(preun): python3, libselinux, selinux-policy-targeted, policycoreutils
Requires(preun): /usr/bin/python3, /usr/bin/semodule, /usr/bin/rpm, /usr/bin/systemctl

%description
The fixed ABI 2 core/context policy pair and its owned lifecycle helpers.
Maintenance requires an administrator-stopped and drained service with concurrent
starts and privileged writers excluded. Installing does not start the service.
Corresponding reference-policy source and notices accompany the derived pair.

%prep

%build

%install
mkdir -p "%{buildroot}"
cp -a "%{qsh_stage}/." "%{buildroot}/"

%pre -f %{qsh_hooks}/provider-pre
%post -f %{qsh_hooks}/provider-post
%preun -f %{qsh_hooks}/provider-preun
%postun -f %{qsh_hooks}/provider-postun

%files
%defattr(0644,root,root,0755)
/usr/libexec/qshd-selinux/qshd_selinux_activation.py
/usr/libexec/qshd-selinux/qshd_selinux_activation_state.py
/usr/libexec/qshd-selinux/qshd_selinux_contexts.py
/usr/libexec/qshd-selinux/qshd_selinux_transaction.py
/usr/libexec/qshd-selinux/qshd_selinux_fs.py
/usr/libexec/qshd-selinux/qshd_selinux_registry.py
/usr/libexec/qshd-selinux/qshd_selinux_process.py
/usr/libexec/qshd-selinux/qshd_selinux_modules.py
/usr/libexec/qshd-selinux/qshd_selinux_module_observer.py
/usr/libexec/qshd-selinux/qshd_selinux_api.py
/usr/libexec/qshd-selinux/qshd_selinux_queries.py
/usr/libexec/qshd-selinux/qshd_selinux_files.py
/usr/libexec/qshd-selinux/qshd_selinux_retained_labels.py
/usr/libexec/qshd-selinux/qshd_selinux_observer.py
/usr/libexec/qshd-selinux/qshd_selinux_reference_loader.py
/usr/libexec/qshd-selinux/qshd_selinux_package_state.py
/usr/libexec/qshd-selinux/qshd_selinux_module_install.py
/usr/libexec/qshd-selinux/qshd_selinux_first_activation.py
/usr/libexec/qshd-selinux/qshd_selinux_consumer_activation.py
/usr/libexec/qshd-selinux/qshd_selinux_provider_erase.py
/usr/libexec/qshd-selinux/qshd_selinux_phase.py
/usr/libexec/qshd-selinux/qshd_selinux_rpm_query.py
/usr/libexec/qshd-selinux/stop_guard.py
/usr/share/qshd-selinux/qshd.pp
/usr/share/qshd-selinux/qshd_contexts.pp
/usr/share/qshd-selinux/artifact.json
/usr/share/qshd-selinux/qshd.fedora-selinux
/usr/share/qshd-selinux/reference.json
/usr/share/qshd-selinux/source/qshd-selinux-%{version}-source.tar.gz
%license /usr/share/licenses/qshd-selinux/LICENSE
%license /usr/share/licenses/qshd-selinux/GPL-3.0.txt
%doc /usr/share/doc/qshd-selinux/README.md
