Name:		cyberprobe
Version:	0.55
Release:	1%{?dist}
Summary:	Distrbuted real-time monitoring of networks against attack.
Group:		Applications/Internet
License:	GPLv3
URL:		http://cyberprobe.sourceforge.net
Source0:	%{name}-%{version}.tar.gz
#BuildRequires:	
#Requires:	

# Compression disabler?
%define _\_os\_install_post %{nil}

%description
The Cyberprobe project is a distrbuted architecture for real-time
monitoring of networks against attack.  The software consists of two components:
- a probe, which collects data packets and forwards it over a network in
standard streaming protocols.
- a monitor, which receives the streamed packets, decodes the protocols,
and interprets the information.

These components can be used together or separately.  For a simple
configuration, they can be run on the same host, for more complex environments,
a number of probes can feed a single monitor.

Please see documentation in /usr/share/doc/cyberprobe.
%prep
%autosetup

%build
%configure
make %{?_smp_mflags}

%install
%make_install

%post
ln -sf %{_docdir}/cyberprobe/cyberprobe-overview.png ${RPM_BUILD_ROOT}%{_infodir}/cyberprobe-overview.png
ln -sf %{_docdir}/cyberprobe/kibana-scaled.png ${RPM_BUILD_ROOT}%{_infodir}/kibana-scaled.png
ln -sf %{_docdir}/cyberprobe/architecture-small.png ${RPM_BUILD_ROOT}%{_infodir}/architecture-small.png

%clean
rm -rf $RPM_BUILD_ROOT

%files
%exclude /usr/share/info/dir
%defattr(-,root,root) 
%doc /usr/share/doc/cyberprobe
%doc /usr/share/info/
%doc /usr/share/man
%dir /etc/cyberprobe
/etc/cyberprobe/*
/usr/bin/*
/usr/lib/python2.7/site-packages/cyberprobe
%{_libdir}/lib*

%changelog
