
bin_PROGRAMS = cyberprobe cybermon nhis11-rcvr etsi-rcvr cyberprobe-cli \
	stream-rcvr tls-rcvr

if WITH_PROTOBUF
if WITH_GRPC
bin_PROGRAMS += eventstream-service
endif
endif

cyberprobe_SOURCES = cyberprobe.C stream/nhis11.C probe/sender.C	\
	probe/delivery.C probe/capture.C probe/configuration.C		\
	probe/control.C probe/snort_alert.C probe/vxlan_capture.C	\
	probe/parameter.C probe/interface.C network/socket.C		\
	resources/resource_manager.C stream/etsi_li.C			\
	../include/cyberprobe/network/socket.h				\
	../include/cyberprobe/stream/etsi_li.h stream/ber.C		\
	../include/cyberprobe/stream/ber.h				\
	../include/cyberprobe/util/address_map.h			\
	../include/cyberprobe/probe/sender.h				\
	../include/cyberprobe/probe/delivery.h				\
	../include/cyberprobe/probe/capture.h probe/endpoint.C		\
	../include/cyberprobe/probe/configuration.h			\
	../include/cyberprobe/probe/control.h				\
	../include/cyberprobe/probe/snort_alert.h			\
	../include/cyberprobe/probe/target.h probe/target.C		\
	../include/cyberprobe/probe/parameterised.h			\
	../include/cyberprobe/probe/packet_consumer.h			\
	../include/cyberprobe/probe/interface.h				\
	../include/cyberprobe/probe/endpoint.h				\
	../include/cyberprobe/probe/parameter.h				\
	../include/cyberprobe/probe/vxlan_capture.h			\
	../include/cyberprobe/probe/management.h

cyberprobe_LDADD = -lssl

if WITH_DAG
cyberprobe_SOURCES += probe/dag_capture.C	\
        ../include/cyberprobe/probe/dag_capture.h
cyberprobe_LDADD += -ldag
endif

cybermon_SOURCES = cybermon.C network/socket.C				\
	../include/cyberprobe/network/socket.h stream/etsi_li.C	\
	../include/cyberprobe/stream/etsi_li.h stream/ber.C	\
	../include/cyberprobe/stream/ber.h

cybermon_LDADD = libcybermon.la -lssl

if WITH_PROTOBUF
if WITH_GRPC
cybermon_LDADD += -lgrpc++ -lgrpc
endif
cybermon_LDADD += -lprotobuf
endif

cyberprobe_cli_SOURCES = cyberprobe-cli.C util/readline.C		\
	../include/cyberprobe/util/readline.h				\
	../include/cyberprobe/probe/interface.h probe/interface.C	\
	../include/cyberprobe/probe/endpoint.h probe/endpoint.C		\
	../include/cyberprobe/probe/parameter.h probe/parameter.C	\
	../include/cyberprobe/probe/target.h probe/target.C		\
	network/socket.C ../include/cyberprobe/network/socket.h
cyberprobe_cli_LDADD = -lssl 

nhis11_rcvr_SOURCES = nhis11_rcvr.C stream/nhis11.C network/socket.C \
	../include/cyberprobe/network/socket.h
nhis11_rcvr_LDADD = -lssl

etsi_rcvr_SOURCES = etsi_rcvr.C network/socket.C		\
	../include/cyberprobe/network/socket.h stream/ber.C	\
	../include/cyberprobe/stream/ber.h stream/etsi_li.C	\
	../include/cyberprobe/stream/etsi_li.h
etsi_rcvr_LDADD =  -lssl

stream_rcvr_SOURCES = stream_rcvr.C network/socket.C	\
        ../include/cyberprobe/network/socket.h
stream_rcvr_LDADD = -lssl

tls_rcvr_SOURCES = tls_rcvr.C network/socket.C	\
        ../include/cyberprobe/network/socket.h
tls_rcvr_LDADD = -lssl

lib_LTLIBRARIES = libcybermon.la

libcybermon_la_SOURCES = protocol/address.C protocol/base_context.C	\
	analyser/lua.C protocol/dns_over_tcp.C				\
	protocol/dns_over_udp.C protocol/dns_protocol.C			\
	analyser/engine.C protocol/forgery.C protocol/ftp.C		\
	protocol/http.C protocol/icmp.C protocol/imap.C			\
	protocol/imap_ssl.C protocol/ip.C protocol/ntp.C		\
	protocol/ntp_protocol.C protocol/pop3.C protocol/pop3_ssl.C	\
	event/event.C util/reaper.C protocol/rtp.C			\
	protocol/rtp_ssl.C protocol/sip.C protocol/sip_context.C	\
	protocol/sip_ssl.C event/event_json.C base64/base64.C		\
	protocol/smtp.C protocol/smtp_auth.C protocol/tcp.C		\
	protocol/tcp_ports.C protocol/udp.C protocol/udp_ports.C	\
	protocol/unrecognised.C protocol/tls_key_exchange.C		\
	stream/vxlan.C util/hardware_addr_utils.C protocol/gre.C	\
	protocol/esp.C protocol/802_11.C protocol/tls.C			\
	protocol/tls_handshake.C protocol/tls_utils.C			\
	../include/base64/base64.h					\
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
libcybermon_la_SOURCES += event/event_protobuf.C
libcybermon_la_SOURCES += ../include/cyberprobe/event/event_protobuf.h
endif

if WITH_PROTOBUF
if WITH_GRPC

libcybermon_la_SOURCES += analyser/grpc.C ../include/cyberprobe/analyser/grpc.h

eventstream_service_SOURCES = eventstream-service.C network/socket.C	\
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
