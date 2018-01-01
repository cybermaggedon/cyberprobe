
dist_doc_DATA = architecture.png cyberprobe.css \
	cyberprobe-overview.png kibana.png \
	../stix/example1.txt ../stix/example2.txt \
	cyberprobe.html kibana-small.png kibana-scaled.png \
	cyberprobe.pdf docker-compose.yml stix-default-combined.json

info_TEXINFOS = cyberprobe.texi

man_MANS = nhis11-rcvr.1 etsi-rcvr.1 cyberprobe.1 cybermon.1 cybermon-gaffer.1 \
	cybermon-elasticsearch.1 cybermon-monitor.1 cybermon-bigquery.1 \
	cybermon-cassandra.1 cyberprobe-cli.1

AM_MAKEINFOHTMLFLAGS = --no-split

EXTRA_DIST = nhis11-rcvr.1.in etsi-rcvr.1.in cyberprobe.1.in cybermon.1.in \
	cybermon-gaffer.1.in cybermon-elasticsearch.1.in cybermon-monitor.1.in \
	cybermon-bigquery.1.in cybermon-cassandra.1.in cyberprobe-cli.1.in \
	cyberprobe-overview.eps kibana-scaled.eps architecture.eps \
	docker-compose.yml.in

# FIXME: chmod needed to get make distcheck to work.
install-data-hook:
	chmod +w $(DESTDIR)$(infodir)
	ln -sf $(docdir)/cyberprobe-overview.png $(DESTDIR)$(infodir)/cyberprobe-overview.png
	ln -sf $(docdir)/architecture.png $(DESTDIR)$(infodir)/architecture.png

do_substitution = sed -e 's,[@]DOCDIR[@],$(docdir),g' \
	-e 's,[@]PACKAGE[@],$(PACKAGE),g' \
	-e 's,[@]LUADIR[@],$(sysconfdir)/$(PACKAGE),g' \
	-e 's,[@]VERSION[@],$(VERSION),g' 

nhis11-rcvr.1: $(srcdir)/nhis11-rcvr.1.in Makefile
	$(do_substitution) < $(srcdir)/nhis11-rcvr.1.in > nhis11-rcvr.1

etsi-rcvr.1: $(srcdir)/etsi-rcvr.1.in Makefile
	$(do_substitution) < $(srcdir)/etsi-rcvr.1.in > etsi-rcvr.1

cyberprobe.1: $(srcdir)/cyberprobe.1.in Makefile
	$(do_substitution) < $(srcdir)/cyberprobe.1.in > cyberprobe.1

cyberprobe-cli.1: $(srcdir)/cyberprobe-cli.1.in Makefile
	$(do_substitution) < $(srcdir)/cyberprobe-cli.1.in > cyberprobe-cli.1

cybermon.1: $(srcdir)/cybermon.1.in Makefile
	$(do_substitution) < $(srcdir)/cybermon.1.in > cybermon.1

cybermon-gaffer.1: $(srcdir)/cybermon-gaffer.1.in Makefile
	$(do_substitution) < $(srcdir)/cybermon-gaffer.1.in > cybermon-gaffer.1

cybermon-cassandra.1: $(srcdir)/cybermon-cassandra.1.in Makefile
	$(do_substitution) < $(srcdir)/cybermon-cassandra.1.in > \
		cybermon-cassandra.1

cybermon-elasticsearch.1: $(srcdir)/cybermon-elasticsearch.1.in Makefile
	$(do_substitution) < $(srcdir)/cybermon-elasticsearch.1.in > cybermon-elasticsearch.1

cybermon-monitor.1: $(srcdir)/cybermon-monitor.1.in Makefile
	$(do_substitution) < $(srcdir)/cybermon-monitor.1.in > cybermon-monitor.1

cybermon-bigquery.1: $(srcdir)/cybermon-bigquery.1.in Makefile
	$(do_substitution) < $(srcdir)/cybermon-bigquery.1.in > cybermon-bigquery.1

docker-compose.yml: $(srcdir)/docker-compose.yml.in Makefile
	$(do_substitution) < $(srcdir)/docker-compose.yml.in > docker-compose.yml

CLEANFILES = nhis11-rcvr.1 etsi-rcvr.1 cyberprobe.1 cyberprobe-cli.1 \
	cybermon.1 \
	cybermon-gaffer.1 cybermon-elasticsearch.1 cybermon-monitor.1 \
	cybermon-bigquery.1 paths.texi cybermon-cassandra.1 docker-compose.yml

cyberprobe_TEXINFOS = paths.texi fdl.texi

# FIXME: Want to put a dependency on the Makefile, so that paths.texi gets
# updated on a change of paths.  However, this causes distcheck to fail.
paths.texi:
	( \
	echo "@set PREFIX $(prefix)"; \
	echo "@set DOCDIR $(docdir)"; \
	echo "@set BINDIR $(bindir)"; \
	echo "@set LIBDIR $(libdir)"; \
	echo "@set SYSCONFDIR $(sysconfdir)"; \
	) > $@
