
bin_PROGRAMS = cyberprobe cybermon nhis11_rcvr etsi_rcvr cyberprobe_cli

cyberprobe_SOURCES = cyberprobe.C nhis11.C resource_manager.C sender.C \
	delivery.C xml.C capture.C configuration.C control.C snort_alert.C
cyberprobe_LDADD = libcybermon.la

cybermon_SOURCES = cybermon.C
cybermon_LDADD = libcybermon.la

cyberprobe_cli_SOURCES = cyberprobe_cli.C readline.C
cyberprobe_cli_LDADD = libcybermon.la

nhis11_rcvr_SOURCES = nhis11_rcvr.C nhis11.C
nhis11_rcvr_LDADD = libcybermon.la

etsi_rcvr_SOURCES = etsi_rcvr.C
etsi_rcvr_LDADD = libcybermon.la

lib_LTLIBRARIES = libcybermon.la

libcybermon_la_SOURCES = engine.C etsi_li.C socket.C ber.C base_context.C \
	ip.C tcp.C udp.C http.C address.C icmp.C cybermon-lua.C reaper.C \
	unrecognised.C dns.C dns_protocol.C forgery.C smtp.C ftp.C

