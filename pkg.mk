
VERSION=0.50

deb:
	rm -rf cyberprobe-${VERSION}
	autoreconf -fi
	./configure
	make dist
	cp cyberprobe-${VERSION}.tar.gz cyberprobe_${VERSION}.orig.tar.gz
	tar xvfz cyberprobe-${VERSION}.tar.gz
	cp -r debian/ cyberprobe-${VERSION}/
	cd cyberprobe-${VERSION}/; dpkg-buildpackage -us -uc

rpm:
	make dist
	rpmbuild --define "_topdir `pwd`/RPM" -ba cyberprobe.spec
	cp cyberprobe-${VERSION}.tar.gz RPM/SOURCES/
	rpmbuild --define "_topdir `pwd`/RPM" -ba cyberprobe.spec

