
dist_doc_DATA = architecture.png cyberprobe.css \
	cyberprobe-overview.png index.html licence.html kibana.png \
	../stix/example1.txt ../stix/example2.txt \
	cyberprobe.html kibana-small.png kibana-scaled.png \
	architecture-small.png cyberprobe.pdf

info_TEXINFOS = cyberprobe.texi

man_MANS = nhis11_rcvr.1 etsi_rcvr.1 cyberprobe.1 cybermon.1

AM_MAKEINFOHTMLFLAGS = --no-split

EXTRA_DIST = nhis11_rcvr.1.in etsi_rcvr.1.in cyberprobe.1.in cybermon.1.in \
	cyberprobe-overview.eps kibana-scaled.eps architecture-small.eps

# FIXME: chmod needed to get make distcheck to work.  Why?
install-data-hook:
	chmod +w $(DESTDIR)$(infodir)
	ln -sf $(docdir)/cyberprobe-overview.png $(DESTDIR)$(infodir)/cyberprobe-overview.png
	ln -sf $(docdir)/kibana-scaled.png $(DESTDIR)$(infodir)/kibana-scaled.png
	ln -sf $(docdir)/architecture-small.png $(DESTDIR)$(infodir)/architecture-small.png

do_substitution = sed -e 's,[@]DOCDIR[@],$(docdir),g' \
	-e 's,[@]PACKAGE[@],$(PACKAGE),g' \
	-e 's,[@]LUADIR[@],$(sysconfdir)/$(PACKAGE),g' \
	-e 's,[@]VERSION[@],$(VERSION),g' 

nhis11_rcvr.1: nhis11_rcvr.1.in Makefile
	$(do_substitution) < nhis11_rcvr.1.in > nhis11_rcvr.1

etsi_rcvr.1: etsi_rcvr.1.in Makefile
	$(do_substitution) < etsi_rcvr.1.in > etsi_rcvr.1

cyberprobe.1: cyberprobe.1.in Makefile
	$(do_substitution) < cyberprobe.1.in > cyberprobe.1

cybermon.1: cybermon.1.in Makefile
	$(do_substitution) < cybermon.1.in > cybermon.1

CLEANFILES = nhis11_rcvr.1 etsi_rcvr.1 cyberprobe.1 cybermon.1 paths.texi

cyberprobe_TEXINFOS = paths.texi fdl.texi

paths.texi: Makefile
	( \
	echo "@set PREFIX $(prefix)"; \
	echo "@set DOCDIR $(docdir)"; \
	echo "@set BINDIR $(bindir)"; \
	echo "@set LIBDIR $(libdir)"; \
	) > $@
