
if HAVE_SYSTEMD
systemdsystemunit_DATA=cyberprobe.service cybermon.service	\
	evs-detector.service evs-cassandra.service		\
	evs-elasticsearch.service evs-gaffer.service		\
	evs-geoip.service
endif

EXTRA_DIST=cyberprobe.service.in cybermon.service.in		\
	evs-detector.service.in evs-cassandra.service.in	\
	evs-elasticsearch.service.in evs-gaffer.service.in	\
	evs-geoip.service.in

CLEANFILES = cyberprobe.service cybermon.service evs-detector.service	\
	evs-cassandra.service evs-elasticsearch.service			\
	evs-gaffer.service evs-geoip.service

do_substitution = sed \
	-e 's,[@]bindir[@],$(bindir),g' \
	-e 's,[@]sysconfdir[@],$(sysconfdir),g' \
	-e 's,[@]PACKAGE[@],$(PACKAGE),g'

cyberprobe.service: cyberprobe.service.in Makefile
	$(do_substitution) < $(srcdir)/cyberprobe.service.in > $@

cybermon.service: cybermon.service.in Makefile
	$(do_substitution) < $(srcdir)/cybermon.service.in > $@

evs-detector.service: evs-detector.service.in Makefile
	$(do_substitution) < $(srcdir)/evs-detector.service.in > $@

evs-geoip.service: evs-geoip.service.in Makefile
	$(do_substitution) < $(srcdir)/evs-geoip.service.in > $@

evs-cassandra.service: evs-cassandra.service.in Makefile
	$(do_substitution) < $(srcdir)/evs-cassandra.service.in > $@

evs-elasticsearch.service: evs-elasticsearch.service.in Makefile
	$(do_substitution) < $(srcdir)/evs-elasticsearch.service.in > $@

evs-gaffer.service: evs-gaffer.service.in Makefile
	$(do_substitution) < $(srcdir)/evs-gaffer.service.in > $@
