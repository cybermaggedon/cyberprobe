
# The `:;' works around a Bash 3.2 bug when the output is not writeable.
$(srcdir)/package.m4: $(top_srcdir)/configure.ac
	:;{ \
	  echo '# Signature of the current package.' && \
	  echo 'm4_define([AT_PACKAGE_NAME],' && \
	  echo '  [$(PACKAGE_NAME)])' && \
	  echo 'm4_define([AT_PACKAGE_TARNAME],' && \
	  echo '  [$(PACKAGE_TARNAME)])' && \
	  echo 'm4_define([AT_PACKAGE_VERSION],' && \
	  echo '  [$(PACKAGE_VERSION)])' && \
	  echo 'm4_define([AT_PACKAGE_STRING],' && \
	  echo '  [$(PACKAGE_STRING)])' && \
	  echo 'm4_define([AT_PACKAGE_BUGREPORT],' && \
	  echo '  [$(PACKAGE_BUGREPORT)])'; \
	  echo 'm4_define([AT_PACKAGE_URL],' && \
	  echo '  [$(PACKAGE_URL)])'; \
	} >'$(srcdir)/package.m4'

EXTRA_DIST = testsuite.at $(srcdir)/package.m4 $(TESTSUITE) \
	atlocal.in \
	samples/cpsfnet.pcap samples/cpsfnet.pcap.indicators \
	samples/cpsfnet.pcap.monitor samples/dns2.pcap \
	samples/dns2.pcap.indicators samples/dns2.pcap.monitor \
	samples/ether.pcap samples/ether.pcap.indicators \
	samples/ether.pcap.monitor samples/exampleorg.pcap \
	samples/exampleorg.pcap.indicators samples/exampleorg.pcap.monitor \
	samples/ftp.pcap samples/ftp.pcap.indicators samples/ftp.pcap.monitor \
	samples/malware.pcap samples/malware.pcap.indicators \
	samples/malware.pcap.monitor samples/smtp.pcap \
	samples/ntp.pcap samples/ntp.pcap.monitor \
	samples/smtp.pcap.indicators samples/smtp.pcap.monitor \
	samples/tcp.pcap samples/tcp.pcap.indicators samples/tcp.pcap.monitor \
	samples/icmp.pcap samples/icmp.pcap.indicators \
	samples/icmp.pcap.monitor samples/dnstcp.pcap \
	samples/dnstcp.pcap.monitor samples/dnstcp.pcap.indicators \
	stix/stix-default-combined.json samples/cpsfnet.pcap.model \
	samples/dns2.pcap.model samples/dnstcp.pcap.model \
	samples/ether.pcap.model samples/exampleorg.pcap.model \
	samples/ftp.pcap.model samples/icmp.pcap.model \
	samples/ntp.pcap.model samples/smtp.pcap.model \
        samples/vlan.pcap samples/vlan.pcap.model \
	samples/vlan.pcap.indicators samples/vlan.pcap.monitor \
        samples/ipv6-smtp.pcap samples/ipv6-smtp.pcap.model \
	samples/ipv6-smtp.pcap.indicators samples/ipv6-smtp.pcap.monitor \
	samples/tcp.pcap.model \
	samples/tls.pcap samples/tls-with-cert.pcap \
	samples/tls.pcap.model samples/tls-with-cert.pcap.model \
	samples/tls.pcap.monitor samples/tls-with-cert.pcap.monitor \
	summarise_json

TESTSUITE = $(srcdir)/testsuite
DISTCLEANFILES = $(TESTSUITE) atconfig
CLEANFILES = package.m4

check-local: atconfig atlocal $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' $(TESTSUITEFLAGS)

installcheck-local: atconfig atlocal $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' AUTOTEST_PATH='$(bindir)' \
	  $(TESTSUITEFLAGS)

clean-local:
	test ! -f '$(TESTSUITE)' || \
	  $(SHELL) '$(TESTSUITE)' --clean

AUTOM4TE = $(SHELL) $(top_srcdir)/missing --run autom4te
AUTOTEST = $(AUTOM4TE) --language=autotest

AM_CPPFLAGS = -I$(srcdir)/../include -I${srcdir}/../src

noinst_PROGRAMS = test_socket test_resource test_address_map

test_socket_SOURCES = test_socket.C ../src/socket.C \
	../include/cyberprobe/network/socket.h
test_socket_LDADD =

test_resource_SOURCES = test_resource.C ../src/resource_manager.C \
	../include/cyberprobe/resources/resource.h
test_resource_LDADD =

test_address_map_SOURCES = test_address_map.C ../src/address_map.h
test_address_map_LDADD =

$(TESTSUITE): $(srcdir)/testsuite.at $(srcdir)/package.m4
	$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	mv $@.tmp $@

