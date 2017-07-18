VERSION=1.0
deb:
	rm -rf cyberprobe-${VERSION}
	autoreconf -fi
	./configure
	make dist
	cp cyberprobe-${VERSION}.tar.gz cyberprobe_${VERSION}.orig.tar.gz
	tar xfz cyberprobe-${VERSION}.tar.gz
	cp -r debian/ cyberprobe-${VERSION}/
	cd cyberprobe-${VERSION}/; dpkg-buildpackage -us -uc

# Hack, Ubuntu libreadline version is different.
ubuntu:
	rm -rf cyberprobe-${VERSION}
	autoreconf -fi
	./configure
	make dist
	cp cyberprobe-${VERSION}.tar.gz cyberprobe_${VERSION}.orig.tar.gz
	tar xfz cyberprobe-${VERSION}.tar.gz
	cp -r debian/ cyberprobe-${VERSION}/
	sed -i 's/libreadline6/libreadline7/g' cyberprobe-${VERSION}/debian/control
	cd cyberprobe-${VERSION}/; dpkg-buildpackage -us -uc

rpm:
	autoreconf -fi
	./configure
	make dist
	mkdir -p RPM/SOURCES
	cp cyberprobe-${VERSION}.tar.gz RPM/SOURCES/
	rpmbuild --define "_topdir `pwd`/RPM" -ba cyberprobe.spec

