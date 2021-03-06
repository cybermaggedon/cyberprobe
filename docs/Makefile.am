
dist_doc_DATA = architecture.png cyberprobe.css				\
	cyberprobe-overview.png kibana.png ../stix/example1.txt		\
	../stix/example2.txt cyberprobe.html kibana-dashboards.json	\
	cyberprobe.pdf docker-compose.yml docker-compose-cp-snort.yml	\
	stix-default-combined.json cyberprobe.cfg snort.rules

info_TEXINFOS = cyberprobe.texi
cyberprobe_TEXINFOS = architecture.texi aws-mirroring.texi		\
	containerisation.texi cyberprobe-boot.texi dag.texi		\
	obtaining.texi overview.texi history.texi pubsub.texi		\
	qs-cybermon-config.texi qs-cybermon.texi qs-cyberprobe.texi	\
	qs-mgmt-if.texi qs-preparation.texi qs-snort.texi		\
	qs-threat-indicators.texi qs-top.texi qs-visualisation.texi	\
	ref-evs-alert.texi ref-evs-cassandra.texi		\
	ref-cybermon-configuration.texi ref-evs-detector.texi	\
	ref-indicators.texi ref-evs-dump.texi			\
	ref-evs-elasticsearch.texi					\
	ref-cybermon-example-configs.texi ref-evs-gaffer.texi	\
	ref-evs-geoip.texi ref-cybermon-invocation.texi		\
	ref-evs-monitor.texi ref-cyberprobe-cli-commands.texi	\
	ref-cyberprobe-cli-invocation.texi ref-cyberprobe-config.texi	\
	ref-eventstream-service-invocation.texi				\
	ref-cyberprobe-invocation.texi ref-elasticsearch-model.texi	\
	ref-etsi-rcvr.texi ref-json-event-format.texi			\
	ref-protobuf-event-format.texi ref-mgmt-protocol.texi		\
	ref-nhis11-rcvr.texi ref-streaming-protocols.texi		\
	ref-taxii-client.texi ref-taxii-server.texi			\
	ref-taxii-sync-json.texi ref-top.texi top.texi version.texi	\
	paths.texi signing.texi fdl.texi

man_MANS = nhis11-rcvr.1 etsi-rcvr.1 cyberprobe.1 cybermon.1		\
	evs-gaffer.1 evs-elasticsearch.1 evs-monitor.1	\
	evs-cassandra.1 cyberprobe-cli.1 evs-alert.1		\
	evs-detector.1 evs-dump.1 evs-geoip.1

AM_MAKEINFOHTMLFLAGS = --no-split

EXTRA_DIST = nhis11-rcvr.1.in etsi-rcvr.1.in cyberprobe.1.in		\
	cybermon.1.in evs-gaffer.1.in				\
	evs-elasticsearch.1.in evs-monitor.1.in		\
	evs-cassandra.1.in cyberprobe-cli.1.in			\
	evs-alert.1.in evs-detector.1.in evs-dump.1.in	\
	evs-geoip.1.in cyberprobe-overview.eps architecture.eps	\
	docker-compose.yml.in docker-compose-cp-snort.yml.in

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

evs-gaffer.1: $(srcdir)/evs-gaffer.1.in Makefile
	$(do_substitution) < $(srcdir)/evs-gaffer.1.in > evs-gaffer.1

evs-cassandra.1: $(srcdir)/evs-cassandra.1.in Makefile
	$(do_substitution) < $(srcdir)/evs-cassandra.1.in > \
		evs-cassandra.1

evs-elasticsearch.1: $(srcdir)/evs-elasticsearch.1.in Makefile
	$(do_substitution) < $(srcdir)/evs-elasticsearch.1.in > evs-elasticsearch.1

evs-monitor.1: $(srcdir)/evs-monitor.1.in Makefile
	$(do_substitution) < $(srcdir)/evs-monitor.1.in > evs-monitor.1

evs-alert.1: $(srcdir)/evs-alert.1.in Makefile
	$(do_substitution) < $(srcdir)/evs-alert.1.in > evs-alert.1

evs-dump.1: $(srcdir)/evs-dump.1.in Makefile
	$(do_substitution) < $(srcdir)/evs-dump.1.in > evs-dump.1

evs-geoip.1: $(srcdir)/evs-geoip.1.in Makefile
	$(do_substitution) < $(srcdir)/evs-geoip.1.in > evs-geoip.1

evs-detector.1: $(srcdir)/evs-detector.1.in Makefile
	$(do_substitution) < $(srcdir)/evs-detector.1.in > evs-detector.1

docker-compose.yml: $(srcdir)/docker-compose.yml.in Makefile
	$(do_substitution) < $(srcdir)/docker-compose.yml.in > docker-compose.yml

docker-compose-cp-snort.yml: $(srcdir)/docker-compose-cp-snort.yml.in Makefile
	$(do_substitution) < $(srcdir)/docker-compose-cp-snort.yml.in > docker-compose-cp-snort.yml

CLEANFILES = nhis11-rcvr.1 etsi-rcvr.1 cyberprobe.1 cyberprobe-cli.1	\
	cybermon.1 evs-gaffer.1 evs-elasticsearch.1		\
	evs-monitor.1 paths.texi		\
	evs-cassandra.1 docker-compose.yml				\
	docker-compose-cp-snort.yml evs-alert.1			\
	evs-detector.1 evs-dump.1 evs-geoip.1

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
