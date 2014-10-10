
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

EXTRA_DIST = testsuite.at $(srcdir)/package.m4 $(TESTSUITE) atlocal.in \
	samples/cpsfnet.pcap samples/cpsfnet.pcap.indicators \
	samples/cpsfnet.pcap.monitor samples/dns2.pcap \
	samples/dns2.pcap.indicators samples/dns2.pcap.monitor \
	samples/ether.pcap samples/ether.pcap.indicators \
	samples/ether.pcap.monitor samples/exampleorg.pcap \
	samples/exampleorg.pcap.indicators samples/exampleorg.pcap.monitor \
	samples/ftp.pcap samples/ftp.pcap.indicators samples/ftp.pcap.monitor \
	samples/malware.pcap samples/malware.pcap.indicators \
	samples/malware.pcap.monitor samples/smtp.pcap \
	samples/smtp.pcap.indicators samples/smtp.pcap.monitor \
	samples/tcp.pcap samples/tcp.pcap.indicators samples/tcp.pcap.monitor \
	stix/stix-default-combined.json

TESTSUITE = $(srcdir)/testsuite
DISTCLEANFILES = $(srcdir)/testsuite $(srcdir)/atconfig

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

$(TESTSUITE): $(srcdir)/testsuite.at $(srcdir)/package.m4
	$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	mv $@.tmp $@

