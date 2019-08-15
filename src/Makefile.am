
bin_PROGRAMS = cyberprobe cybermon nhis11-rcvr etsi-rcvr cyberprobe-cli \
	stream-rcvr tls-rcvr

if WITH_PROTOBUF
if WITH_GRPC
bin_PROGRAMS += decode_protobuf
endif
endif

cyberprobe_SOURCES = cyberprobe.C nhis11.C sender.C \
	delivery.C capture.C configuration.C control.C snort_alert.C \
	sender.h delivery.h capture.h endpoint.C \
	configuration.h control.h snort_alert.h target.h target.C \
	parameters.h packet_consumer.h interface.h interface.C \
	endpoint.h parameter.h parameter.C \
	vxlan_capture.h vxlan_capture.C socket.C resource_manager.C \
	../include/cybermon/socket.h etsi_li.C ../include/cybermon/etsi_li.h \
	ber.C ../include/cybermon/ber.h address_map.h

cyberprobe_LDADD = -lssl

if WITH_DAG
cyberprobe_SOURCES += dag_capture.C dag_capture.h
cyberprobe_LDADD += -ldag
endif

cybermon_SOURCES = cybermon.C management.h  socket.C \
	../include/cybermon/socket.h etsi_li.C ../include/cybermon/etsi_li.h \
	ber.C ../include/cybermon/ber.h
cybermon_LDADD = libcybermon.la -lssl

if WITH_PROTOBUF
if WITH_GRPC
cybermon_LDADD += -lgrpc++ -lgrpc
endif
cybermon_LDADD += -lprotobuf
endif

cyberprobe_cli_SOURCES = cyberprobe-cli.C readline.C readline.h interface.h \
	interface.C endpoint.h endpoint.C parameter.h parameter.C \
	target.h target.C socket.C ../include/cybermon/socket.h
cyberprobe_cli_LDADD = -lssl 

nhis11_rcvr_SOURCES = nhis11_rcvr.C nhis11.C socket.C \
	../include/cybermon/socket.h
nhis11_rcvr_LDADD = -lssl

etsi_rcvr_SOURCES = etsi_rcvr.C socket.C ../include/cybermon/socket.h \
	ber.C ../include/cybermon/ber.h etsi_li.C ../include/cybermon/etsi_li.h
etsi_rcvr_LDADD =  -lssl

stream_rcvr_SOURCES = stream_rcvr.C socket.C ../include/cybermon/socket.h
stream_rcvr_LDADD = -lssl

tls_rcvr_SOURCES = tls_rcvr.C socket.C ../include/cybermon/socket.h
tls_rcvr_LDADD = -lssl

lib_LTLIBRARIES = libcybermon.la

libcybermon_la_SOURCES = address.C base_context.C 		\
	cybermon-lua.C dns_over_tcp.C dns_over_udp.C dns_protocol.C	\
	engine.C  forgery.C ftp.C http.C icmp.C imap.C		\
	imap_ssl.C ip.C ntp.C ntp_protocol.C pop3.C pop3_ssl.C event.C  \
	reaper.C rtp.C rtp_ssl.C sip.C sip_context.C \
	sip_ssl.C	event_json.C \
	base64.C base64.h json.h \
	smtp.C smtp_auth.C tcp.C tcp_ports.C udp.C udp_ports.C \
	unrecognised.C \
	tls_key_exchange.C vxlan.C \
	hardware_addr_utils.C gre.C esp.C 802_11.C tls.C tls_handshake.C \
	tls_utils.C \
	hardware_addr_utils.h tls_cipher_suites.h tls_exception.h \
	tls_extensions.h \
	tls_handshake.h tls_key_exchange.h tls_utils.h \
	../include/cybermon/address.h 	\
	uuid.h	                \
	../include/cybermon/base_context.h				\
	../include/cybermon/context.h					\
	../include/cybermon/cybermon-lua.h				\
	../include/cybermon/dns_context.h				\
	../include/cybermon/dns_over_tcp.h				\
	../include/cybermon/dns_over_udp.h				\
	../include/cybermon/dns_protocol.h				\
	../include/cybermon/engine.h 	\
	../include/cybermon/exception.h ../include/cybermon/forgery.h	\
	../include/cybermon/flow.h ../include/cybermon/ftp.h		\
	../include/cybermon/http.h ../include/cybermon/icmp.h		\
	../include/cybermon/imap.h ../include/cybermon/imap_context.h	\
	../include/cybermon/imap_ssl.h					\
	../include/cybermon/imap_ssl_context.h				\
	../include/cybermon/ip.h ../include/cybermon/manager.h		\
	../include/cybermon/monitor.h ../include/cybermon/nhis11.h	\
	../include/cybermon/ntp.h ../include/cybermon/ntp_protocol.h	\
	../include/cybermon/observer.h					\
	../include/cybermon/event.h					\
	../include/cybermon/event_implementations.h			\
	../include/cybermon/event_json.h  \
	../include/cybermon/packet_capture.h				\
	../include/cybermon/pdu.h ../include/cybermon/pop3.h		\
	../include/cybermon/pop3_context.h				\
	../include/cybermon/pop3_ssl.h					\
	../include/cybermon/pop3_ssl_context.h				\
	../include/cybermon/protocol.h ../include/cybermon/reaper.h	\
	../include/cybermon/resource.h ../include/cybermon/rtp.h	\
	../include/cybermon/rtp_context.h				\
	../include/cybermon/rtp_ssl.h ../include/cybermon/serial.h	\
	../include/cybermon/sip.h ../include/cybermon/sip_context.h	\
	../include/cybermon/sip_ssl.h ../include/cybermon/smtp.h	\
	../include/cybermon/smtp_auth.h					\
	../include/cybermon/smtp_auth_context.h				\
	../include/cybermon/specification.h ../include/cybermon/tcp.h	\
	../include/cybermon/transport.h	\
	../include/cybermon/udp.h ../include/cybermon/unrecognised.h	\
	../include/cybermon/gre.h ../include/cybermon/esp.h \
	../include/cybermon/802_11.h \
	../include/cybermon/tls_handshake_protocol.h \
	../include/cybermon/tls.h \
	../include/cybermon/vxlan.h \
	../include/cybermon/event_queue.h

if WITH_PROTOBUF
libcybermon_la_SOURCES += event_protobuf.C
libcybermon_la_SOURCES += ../include/cybermon/event_protobuf.h
endif

if WITH_PROTOBUF
if WITH_GRPC

libcybermon_la_SOURCES += event_grpc.C

decode_protobuf_SOURCES = decode_protobuf.C socket.C \
	../include/cybermon/socket.h
decode_protobuf_LDADD = libcybermon.la -lssl -lgrpc++ -lgrpc -lprotobuf

endif
endif

ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = -I$(top_srcdir)/include
AM_LDFLAGS = 

LDFLAGS_BOOST = \
    $(BOOST_REGEX_LDFLAGS) $(BOOST_PROGRAM_OPTIONS_LDFLAGS)

LIBS_BOOST = \
    $(BOOST_REGEX_LIBS) $(BOOST_PROGRAM_OPTIONS_LIBS)

AM_CPPFLAGS += $(BOOST_CPPFLAGS) $(LUA_INCLUDE)
AM_LDFLAGS += $(LDFLAGS_BOOST) $(LUA_LDADD)
LIBS += $(LIBS_BOOST) $(LUA_LIB)

BUILT_SOURCES =
MOSTLYCLEANFILES =
nodist_libcybermon_la_SOURCES =
dist_noinst_DATA =

if WITH_PROTOBUF

cyberprobe.pb.cc cyberprobe.pb.h: ../protos/cyberprobe.proto
	$(PROTOC) --proto_path=$(srcdir)/../protos --cpp_out=$(builddir) $^

dist_noinst_DATA += ../protos/cyberprobe.proto

MOSTLYCLEANFILES += cyberprobe.pb.cc cyberprobe.pb.h

nodist_libcybermon_la_SOURCES += $(builddir)/cyberprobe.pb.cc \
	$(builddir)/cyberprobe.pb.h

BUILT_SOURCES += cyberprobe.pb.h

if WITH_GRPC

cyberprobe.grpc.pb.cc cyberprobe.grpc.pb.h: ../protos/cyberprobe.proto
	$(PROTOC) --proto_path=$(srcdir)/../protos \
	    --grpc_out=$(builddir) \
	    --plugin=protoc-gen-grpc=$$(which grpc_cpp_plugin) $<

MOSTLYCLEANFILES += cyberprobe.grpc.pb.cc cyberprobe.grpc.pb.h

nodist_libcybermon_la_SOURCES += $(builddir)/cyberprobe.grpc.pb.cc \
	$(builddir)/cyberprobe.grpc.pb.h

BUILT_SOURCES += cyberprobe.grpc.pb.h

endif

endif
