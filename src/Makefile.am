
bin_PROGRAMS = cyberprobe cybermon nhis11_rcvr etsi_rcvr cyberprobe_cli

cyberprobe_SOURCES = cyberprobe.C nhis11.C resource_manager.C sender.C \
	delivery.C xml.C capture.C configuration.C control.C snort_alert.C \
	nhis11.h resource.h sender.h delivery.h xml.h capture.h \
	configuration.h control.h snort_alert.h target.h specification.h \
	parameters.h packet_capture.h packet_consumer.h interface.h \
	endpoint.h parameter.h
cyberprobe_LDADD = libcybermon.la

cybermon_SOURCES = cybermon.C
cybermon_LDADD = libcybermon.la

cyberprobe_cli_SOURCES = cyberprobe_cli.C readline.C readline.h
cyberprobe_cli_LDADD = libcybermon.la

nhis11_rcvr_SOURCES = nhis11_rcvr.C nhis11.C
nhis11_rcvr_LDADD = libcybermon.la

etsi_rcvr_SOURCES = etsi_rcvr.C
etsi_rcvr_LDADD = libcybermon.la

lib_LTLIBRARIES = libcybermon.la

libcybermon_la_SOURCES = engine.C etsi_li.C socket.C ber.C base_context.C \
	ip.C tcp.C udp.C http.C address.C icmp.C cybermon-lua.C reaper.C \
	unrecognised.C dns.C dns_protocol.C forgery.C smtp.C ftp.C engine.h \
	etsi_li.h socket.h ber.h base_context.h ip.h tcp.h udp.h http.h \
	address.h icmp.h cybermon-lua.h reaper.h unrecognised.h dns.h \
	dns_protocol.h forgery.h smtp.h ftp.h thread.h context.h pdu.h \
	exception.h flow.h manager.h observer.h monitor.h transport.h \
	serial.h protocol.h management.h

ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS =
AM_LDFLAGS = 

LDFLAGS_BOOST = \
    $(BOOST_REGEX_LDFLAGS)

LIBS_BOOST = \
    $(BOOST_REGEX_LIBS)

AM_CPPFLAGS += $(BOOST_CPPFLAGS)
AM_LDFLAGS += $(LDFLAGS_BOOST)
LIBS += $(LIBS_BOOST) $(LUA_LIB)

