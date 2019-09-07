
bin_PROGRAMS = cyberprobe cybermon nhis11-rcvr etsi-rcvr cyberprobe-cli \
	stream-rcvr tls-rcvr

if WITH_PROTOBUF
if WITH_GRPC
bin_PROGRAMS += eventstream-service
endif
endif

cyberprobe_SOURCES = cyberprobe.C nhis11.C sender.C delivery.C	\
	capture.C configuration.C control.C snort_alert.C	\
	vxlan_capture.C parameter.C interface.C socket.C	\
	resource_manager.C etsi_li.C				\
	../include/cyberprobe/network/socket.h			\
	../include/cyberprobe/stream/etsi_li.h ber.C		\
	../include/cyberprobe/stream/ber.h			\
	../include/cyberprobe/util/address_map.h		\
	../include/cyberprobe/probe/sender.h			\
	../include/cyberprobe/probe/delivery.h			\
	../include/cyberprobe/probe/capture.h endpoint.C	\
	../include/cyberprobe/probe/configuration.h		\
	../include/cyberprobe/probe/control.h			\
	../include/cyberprobe/probe/snort_alert.h		\
	../include/cyberprobe/probe/target.h target.C		\
	../include/cyberprobe/probe/parameterised.h		\
	../include/cyberprobe/probe/packet_consumer.h		\
	../include/cyberprobe/probe/interface.h			\
	../include/cyberprobe/probe/endpoint.h			\
	../include/cyberprobe/probe/parameter.h			\
	../include/cyberprobe/probe/vxlan_capture.h
	../include/cyberprobe/probe/management.h

cyberprobe_LDADD = -lssl

if WITH_DAG
cyberprobe_SOURCES += dag_capture.C ../include/cyberprobe/probe/dag_capture.h
cyberprobe_LDADD += -ldag
endif

cybermon_SOURCES = cybermon.C socket.C		\
	../include/cyberprobe/network/socket.h etsi_li.C	\
	../include/cyberprobe/stream/etsi_li.h ber.C		\
	../include/cyberprobe/stream/ber.h

cybermon_LDADD = libcybermon.la -lssl

if WITH_PROTOBUF
if WITH_GRPC
cybermon_LDADD += -lgrpc++ -lgrpc
endif
cybermon_LDADD += -lprotobuf
endif

cyberprobe_cli_SOURCES = cyberprobe-cli.C readline.C readline.h		\
	interface.h interface.C endpoint.h endpoint.C parameter.h	\
	parameter.C target.h target.C socket.C				\
	../include/cyberprobe/network/socket.h
cyberprobe_cli_LDADD = -lssl 

nhis11_rcvr_SOURCES = nhis11_rcvr.C nhis11.C socket.C \
	../include/cyberprobe/network/socket.h
nhis11_rcvr_LDADD = -lssl

etsi_rcvr_SOURCES = etsi_rcvr.C socket.C		\
	../include/cyberprobe/network/socket.h ber.C	\
	../include/cyberprobe/stream/ber.h etsi_li.C	\
	../include/cyberprobe/stream/etsi_li.h
etsi_rcvr_LDADD =  -lssl

stream_rcvr_SOURCES = stream_rcvr.C socket.C	\
        ../include/cyberprobe/network/socket.h
stream_rcvr_LDADD = -lssl

tls_rcvr_SOURCES = tls_rcvr.C socket.C ../include/cyberprobe/network/socket.h
tls_rcvr_LDADD = -lssl

lib_LTLIBRARIES = libcybermon.la

libcybermon_la_SOURCES = address.C base_context.C lua.C			\
	dns_over_tcp.C dns_over_udp.C dns_protocol.C engine.C		\
	forgery.C ftp.C http.C icmp.C imap.C imap_ssl.C ip.C ntp.C	\
	ntp_protocol.C pop3.C pop3_ssl.C event.C reaper.C rtp.C		\
	rtp_ssl.C sip.C sip_context.C sip_ssl.C event_json.C base64.C	\
	smtp.C smtp_auth.C tcp.C tcp_ports.C udp.C udp_ports.C		\
	unrecognised.C tls_key_exchange.C vxlan.C			\
	hardware_addr_utils.C gre.C esp.C 802_11.C tls.C		\
	tls_handshake.C tls_utils.C ../include/base64/base64.h		\
	../include/cyberprobe/util/hardware_addr_utils.h		\
	../include/cyberprobe/protocol/tls_cipher_suites.h		\
	../include/cyberprobe/protocol/tls_exception.h			\
	../include/cyberprobe/protocol/tls_extensions.h			\
	../include/cyberprobe/protocol/tls_handshake.h			\
	../include/cyberprobe/protocol/tls_key_exchange.h		\
	../include/cyberprobe/protocol/tls_utils.h			\
	../include/cyberprobe/util/uuid.h ../include/nlohmann/json.h	\
	../include/cyberprobe/analyser/lua.h				\
	../include/cyberprobe/analyser/engine.h				\
	../include/cyberprobe/protocol/manager.h			\
	../include/cyberprobe/analyser/monitor.h			\
	../include/cyberprobe/protocol/observer.h			\
	../include/cyberprobe/protocol/process.h			\
	../include/cyberprobe/event/event.h				\
	../include/cyberprobe/event/event_implementations.h		\
	../include/cyberprobe/event/event_json.h			\
	../include/cyberprobe/event/event_queue.h			\
	../include/cyberprobe/exception.h				\
	../include/cyberprobe/pkt_capture/packet_capture.h		\
	../include/cyberprobe/protocol/802_11.h				\
	../include/cyberprobe/protocol/address.h			\
	../include/cyberprobe/protocol/base_context.h			\
	../include/cyberprobe/protocol/context.h			\
	../include/cyberprobe/protocol/dns_context.h			\
	../include/cyberprobe/protocol/dns_over_tcp.h			\
	../include/cyberprobe/protocol/dns_over_udp.h			\
	../include/cyberprobe/protocol/dns_protocol.h			\
	../include/cyberprobe/protocol/esp.h				\
	../include/cyberprobe/protocol/flow.h				\
	../include/cyberprobe/protocol/forgery.h			\
	../include/cyberprobe/protocol/ftp.h				\
	../include/cyberprobe/protocol/gre.h				\
	../include/cyberprobe/protocol/http.h				\
	../include/cyberprobe/protocol/icmp.h				\
	../include/cyberprobe/protocol/imap.h				\
	../include/cyberprobe/protocol/imap_context.h			\
	../include/cyberprobe/protocol/imap_ssl.h			\
	../include/cyberprobe/protocol/imap_ssl_context.h		\
	../include/cyberprobe/protocol/ip.h				\
	../include/cyberprobe/protocol/ntp.h				\
	../include/cyberprobe/protocol/ntp_protocol.h			\
	../include/cyberprobe/protocol/pdu.h				\
	../include/cyberprobe/protocol/pop3.h				\
	../include/cyberprobe/protocol/pop3_context.h			\
	../include/cyberprobe/protocol/pop3_ssl.h			\
	../include/cyberprobe/protocol/pop3_ssl_context.h		\
	../include/cyberprobe/protocol/rtp.h				\
	../include/cyberprobe/protocol/rtp_context.h			\
	../include/cyberprobe/protocol/rtp_ssl.h			\
	../include/cyberprobe/protocol/sip.h				\
	../include/cyberprobe/protocol/sip_context.h			\
	../include/cyberprobe/protocol/sip_ssl.h			\
	../include/cyberprobe/protocol/smtp.h				\
	../include/cyberprobe/protocol/smtp_auth.h			\
	../include/cyberprobe/protocol/smtp_auth_context.h		\
	../include/cyberprobe/protocol/tcp.h				\
	../include/cyberprobe/protocol/tcp_ports.h			\
	../include/cyberprobe/protocol/tls.h				\
	../include/cyberprobe/protocol/tls_handshake_protocol.h		\
	../include/cyberprobe/protocol/udp.h				\
	../include/cyberprobe/protocol/udp_ports.h			\
	../include/cyberprobe/protocol/unrecognised.h			\
	../include/cyberprobe/resources/resource.h			\
	../include/cyberprobe/resources/specification.h			\
	../include/cyberprobe/stream/nhis11.h				\
	../include/cyberprobe/stream/transport.h			\
	../include/cyberprobe/stream/vxlan.h				\
	../include/cyberprobe/util/reaper.h				\
	../include/cyberprobe/util/serial.h

if WITH_PROTOBUF
libcybermon_la_SOURCES += event_protobuf.C
libcybermon_la_SOURCES += ../include/cyberprobe/event/event_protobuf.h
endif

if WITH_PROTOBUF
if WITH_GRPC

libcybermon_la_SOURCES += event_grpc.C

eventstream_service_SOURCES = eventstream-service.C socket.C \
	../include/cyberprobe/network/socket.h
eventstream_service_LDADD = libcybermon.la -lssl -lgrpc++ -lgrpc -lprotobuf

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
	$(PROTOC) --proto_path=$(srcdir)/../protos --cpp_out=. $^

dist_noinst_DATA += ../protos/cyberprobe.proto
nodist_libcybermon_la_SOURCES += cyberprobe.pb.cc cyberprobe.pb.h
BUILT_SOURCES += cyberprobe.pb.h
MOSTLYCLEANFILES += cyberprobe.pb.cc cyberprobe.pb.h

if WITH_GRPC

cyberprobe.grpc.pb.cc cyberprobe.grpc.pb.h: ../protos/cyberprobe.proto
	$(PROTOC) --proto_path=$(srcdir)/../protos \
	    --grpc_out=. \
	    --plugin=protoc-gen-grpc=$$(which grpc_cpp_plugin) $<

nodist_libcybermon_la_SOURCES += cyberprobe.grpc.pb.cc cyberprobe.grpc.pb.h
MOSTLYCLEANFILES += cyberprobe.grpc.pb.cc cyberprobe.grpc.pb.h
BUILT_SOURCES += cyberprobe.grpc.pb.h

endif

endif
