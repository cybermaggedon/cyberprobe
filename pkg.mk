
VERSION=0.70

deb:
	rm -rf cyberprobe-${VERSION}
	autoreconf -fi
	./configure
	make distcheck
	cp cyberprobe-${VERSION}.tar.gz cyberprobe_${VERSION}.orig.tar.gz
	tar xvfz cyberprobe-${VERSION}.tar.gz
	cp -r debian/ cyberprobe-${VERSION}/
	cd cyberprobe-${VERSION}/; dpkg-buildpackage -us -uc

rpm:
	autoreconf -fi
	./configure
	make distcheck
	mkdir -p RPM/SOURCES
	cp cyberprobe-${VERSION}.tar.gz RPM/SOURCES/
	rpmbuild --define "_topdir `pwd`/RPM" -ba cyberprobe.spec

