%define name cb-response-bigfix-connector
%define version 2016.9.8.23.2.9
%define unmangled_version 2016.9.8.23.2.9
%define release 1
%global _enable_debug_package 0
%global debug_package %{nil}
%global __os_install_post /usr/lib/rpm/brp-compress %{nil}

Summary: Carbon Black Response, Bigfix Integration
Name: %{name}
Version: %{version}
Release: %{release}
Source0: %{name}-%{unmangled_version}.tar.gz
License: MIT
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: x86_64
Vendor: Carbon Black
Url: http://www.carbonblack.com/

%description
UNKNOWN

%prep
%setup -n %{name}-%{unmangled_version}

%build
pyinstaller pyinstaller.spec

%install
python setup.py install_cb --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES

%clean
rm -rf $RPM_BUILD_ROOT

%posttrans
# not auto-starting because conf needs to be updated
start cb-response-bigfix-connector

%preun
# run the null command here to ensure we always return success
# otherwise the uninstall would stop if we couldn't halt the service
stop cb-response-bigfix-connector || :

%files -f INSTALLED_FILES
%defattr(-,root,root)
