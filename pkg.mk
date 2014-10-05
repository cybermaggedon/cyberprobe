
deb:
	rm -rf cyberprobe-0.50
	autoreconf -fi
	./configure
	make dist
	cp cyberprobe-0.50.tar.gz cyberprobe_0.50.orig.tar.gz
	tar xvfz cyberprobe-0.50.tar.gz
	cp -r debian/ cyberprobe-0.50/
	cd cyberprobe-0.50/; dpkg-buildpackage -us -uc

