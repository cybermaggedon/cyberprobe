
bin_PROGRAMS = cyberprobe cybermon nhis11_rcvr etsi_rcvr cyberprobe_cli

cyberprobe_SOURCES = cyberprobe.C socket.C nhis11.C etsi_li.C \
	resource_manager.C sender.C delivery.C xml.C ber.C capture.C \
	configuration.C control.C snort_alert.C

cybermon_SOURCES = cybermon.C engine.C etsi_li.C socket.C ber.C base_context.C \
	ip.C tcp.C udp.C http.C address.C icmp.C cybermon-lua.C reaper.C \
	unrecognised.C dns.C dns_protocol.C forgery.C smtp.C ftp.C

cyberprobe_cli_SOURCES = cyberprobe_cli.C socket.C readline.C

nhis11_rcvr_SOURCES = nhis11_rcvr.C nhis11.C socket.C

etsi_rcvr_SOURCES = etsi_rcvr.C etsi_li.C socket.C ber.C

