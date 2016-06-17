
if HAVE_SYSTEMD
systemdsystemunit_DATA = cyberprobe.service cybermon.service
endif

EXTRA_DIST=cyberprobe.service.in cybermon.service.in

CLEANFILES = cyberprobe.service cybermon.service

do_substitution = sed \
	-e 's,[@]bindir[@],$(bindir),g' \
	-e 's,[@]sysconfdir[@],$(sysconfdir),g' \
	-e 's,[@]PACKAGE[@],$(PACKAGE),g'

cyberprobe.service: cyberprobe.service.in Makefile
	$(do_substitution) < $(srcdir)/cyberprobe.service.in > $@

cybermon.service: cybermon.service.in Makefile
	$(do_substitution) < $(srcdir)/cybermon.service.in > $@


