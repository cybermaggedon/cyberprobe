
if HAVE_SYSTEMD
systemdsystemunit_DATA=cyberprobe.service cybermon.service \
	cybermon-bigquery.service cybermon-cassandra.service \
	cybermon-elasticsearch.service cybermon-gaffer.service
endif

EXTRA_DIST=cyberprobe.service.in cybermon.service.in \
	cybermon-bigquery.service.in cybermon-cassandra.service.in \
	cybermon-elasticsearch.service.in cybermon-gaffer.service.in

CLEANFILES = cyberprobe.service cybermon.service \
	cybermon-bigquery.service cybermon-cassandra.service \
	cybermon-elasticsearch.service cybermon-gaffer.service

do_substitution = sed \
	-e 's,[@]bindir[@],$(bindir),g' \
	-e 's,[@]sysconfdir[@],$(sysconfdir),g' \
	-e 's,[@]PACKAGE[@],$(PACKAGE),g'

cyberprobe.service: cyberprobe.service.in Makefile
	$(do_substitution) < $(srcdir)/cyberprobe.service.in > $@

cybermon.service: cybermon.service.in Makefile
	$(do_substitution) < $(srcdir)/cybermon.service.in > $@

cybermon-bigquery.service: cybermon-bigquery.service.in Makefile
	$(do_substitution) < $(srcdir)/cybermon-bigquery.service.in > $@

cybermon-cassandra.service: cybermon-cassandra.service.in Makefile
	$(do_substitution) < $(srcdir)/cybermon-cassandra.service.in > $@

cybermon-elasticsearch.service: cybermon-elasticsearch.service.in Makefile
	$(do_substitution) < $(srcdir)/cybermon-elasticsearch.service.in > $@

cybermon-gaffer.service: cybermon-gaffer.service.in Makefile
	$(do_substitution) < $(srcdir)/cybermon-gaffer.service.in > $@
