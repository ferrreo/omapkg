Name: demo
Version: 1.0
Release: 1
Summary: template matrix RPM fixture
License: MIT
BuildArch: x86_64

%description
Template matrix RPM fixture.

%install
mkdir -p %{buildroot}/usr/share/demo
printf 'rpm payload\n' > %{buildroot}/usr/share/demo/payload.txt

%files
/usr/share/demo/payload.txt
