
dist_doc_DATA = architecture.png cyberprobe.css \
	cyberprobe.png index.html licence.html kibana-scaled.png \
	../stix/example1.txt ../stix/example2.txt \
	cyberprobe.html

info_TEXINFOS = cyberprobe.texi

man_MANS = nhis_rcvr.1 etsi_rcvr.1 cyberprobe.1

AM_MAKEINFOHTMLFLAGS = --no-split

EXTRA_DIST = nhis_rcvr.1.in etsi_rcvr.1.in cyberprobe.1.in

do_substitution = sed -e 's,[@]DOCDIR[@],$(docdir),g' \
	-e 's,[@]PACKAGE[@],$(PACKAGE),g' \
	-e 's,[@]VERSION[@],$(VERSION),g' 

nhis_rcvr.1: nhis_rcvr.1.in Makefile
	$(do_substitution) < $(srcdir)/$< > $@

etsi_rcvr.1: etsi_rcvr.1.in Makefile
	$(do_substitution) < $(srcdir)/$< > $@

cyberprobe.1: cyberprobe.1.in Makefile
	$(do_substitution) < $(srcdir)/$< > $@

CLEANFILES = nhis_rcvr.1 etsi_rcvr.1 cyberprobe.1 paths.texi

cyberprobe_TEXINFOS = paths.texi fdl.texi

paths.texi: Makefile
	( \
	echo "@set PREFIX $(prefix)"; \
	echo "@set DOCDIR $(docdir)"; \
	echo "@set BINDIR $(bindir)"; \
	echo "@set LIBDIR $(libdir)"; \
	) > $@
