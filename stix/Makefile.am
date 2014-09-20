
bin_SCRIPTS = stix-create taxii-server taxii-client \
	taxii-sync taxii-sync-json taxii-push

EXTRA_DIST = stix-create taxii-server.in taxii-client.in \
	taxii-sync taxii-sync-json taxii-push

cyberprobe_PYTHON = cyberprobe/stix_store.py \
	cyberprobe/gmt.py cyberprobe/taxii_query.py cyberprobe/taxii_client.py \
	cyberprobe/taxii_server.py cyberprobe/indicator.py \
	cyberprobe/sync.py cyberprobe/__init__.py

cyberprobedir = $(pythondir)/cyberprobe

do_substitution = sed -e 's,[@]pythondir[@],$(pythondir),g' \
	-e 's,[@]PACKAGE[@],$(PACKAGE),g' \
	-e 's,[@]VERSION[@],$(VERSION),g' 

taxii-server: taxii-server.in Makefile
	$(do_substitution) < $(srcdir)/taxii-server.in > taxii-server
	chmod +x taxii-server

taxii-client: taxii-client.in Makefile
	$(do_substitution) < $(srcdir)/taxii-client.in > taxii-client
	chmod +x taxii-client

