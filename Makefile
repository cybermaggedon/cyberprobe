
CXXFLAGS += -I. -O6 -Wall -Werror

CYBERPROBE_OBJECTS=cyberprobe.o socket.o nhis11.o etsi_li.o \
	resource_manager.o sender.o delivery.o xml.o ber.o capture.o config.o \
	control.o snort_alert.o

CYBERMON_OBJECTS=cybermon.o engine.o etsi_li.o socket.o ber.o base_context.o \
	ip.o tcp.o udp.o http.o address.o icmp.o cybermon-lua.o reaper.o \
	unrecognised.o dns.o dns_protocol.o forgery.o

CYBERPROBE_CLI_OBJECTS=cyberprobe_cli.o socket.o readline.o

all: cyberprobe cybermon nhis11_rcvr etsi_rcvr cyberprobe_cli

cyberprobe: ${CYBERPROBE_OBJECTS}
	${CXX} ${CXXFLAGS} ${CYBERPROBE_OBJECTS} -o $@ -lpcap -lpthread -lexpat

cyberprobe_cli: ${CYBERPROBE_CLI_OBJECTS}
	${CXX} ${CXXFLAGS} ${CYBERPROBE_CLI_OBJECTS} -o $@ -lpcap -lpthread \
		-lexpat -lreadline -lncurses

cybermon: ${CYBERMON_OBJECTS}
	${CXX} ${CXXFLAGS} ${CYBERMON_OBJECTS} -o $@ -lpcap -lpthread -lexpat \
		-llua -lboost_regex

nhis11_rcvr: nhis11_rcvr.o nhis11.o socket.o
	${CXX} ${CXXFLAGS} nhis11_rcvr.o nhis11.o socket.o -o $@ -lpthread \
	  -lpcap

etsi_rcvr: etsi_rcvr.o etsi_li.o socket.o ber.o
	${CXX} ${CXXFLAGS} etsi_rcvr.o etsi_li.o socket.o ber.o -o $@ \
	  -lpthread -lpcap

depend:
	makedepend -Y. *.C

# DO NOT DELETE

address.o: socket.h address.h pdu.h exception.h
base_context.o: base_context.h flow.h address.h pdu.h socket.h exception.h
base_context.o: thread.h
ber.o: ./ber.h socket.h
capture.o: capture.h packet_capture.h packet_consumer.h thread.h
config.o: config.h resource.h thread.h specification.h delivery.h sender.h
config.o: management.h socket.h nhis11.h monitor.h etsi_li.h ./ber.h
config.o: parameters.h capture.h packet_capture.h packet_consumer.h xml.h
config.o: interface.h target.h endpoint.h parameter.h snort_alert.h control.h
context.o: context.h socket.h address.h pdu.h exception.h flow.h reaper.h
context.o: thread.h base_context.h manager.h observer.h dns_protocol.h
control.o: control.h socket.h thread.h management.h specification.h
control.o: resource.h
cybermon.o: engine.h thread.h pdu.h context.h socket.h address.h exception.h
cybermon.o: flow.h reaper.h base_context.h manager.h observer.h
cybermon.o: dns_protocol.h monitor.h etsi_li.h ./ber.h packet_capture.h
cybermon.o: hexdump.h cybermon-lua.h
cybermon-lua.o: cybermon-lua.h engine.h thread.h pdu.h context.h socket.h
cybermon-lua.o: address.h exception.h flow.h reaper.h base_context.h
cybermon-lua.o: manager.h observer.h dns_protocol.h forgery.h
cyberprobe.o: config.h resource.h thread.h specification.h delivery.h
cyberprobe.o: sender.h management.h socket.h nhis11.h monitor.h etsi_li.h
cyberprobe.o: ./ber.h parameters.h capture.h packet_capture.h
cyberprobe.o: packet_consumer.h
cyberprobe_cli.o: readline.h rlwrap.h socket.h
delivery.o: delivery.h sender.h management.h socket.h thread.h nhis11.h
delivery.o: monitor.h etsi_li.h ./ber.h parameters.h capture.h
delivery.o: packet_capture.h packet_consumer.h
dns.o: dns.h context.h socket.h address.h pdu.h exception.h flow.h reaper.h
dns.o: thread.h base_context.h manager.h observer.h dns_protocol.h serial.h
dns.o: protocol.h udp.h ip.h
dns_protocol.o: dns_protocol.h pdu.h address.h socket.h exception.h
engine.o: thread.h context.h socket.h address.h pdu.h exception.h flow.h
engine.o: reaper.h base_context.h manager.h observer.h dns_protocol.h
engine.o: engine.h ip.h
etsi_li.o: etsi_li.h socket.h ./ber.h thread.h monitor.h
etsi_rcvr.o: monitor.h socket.h etsi_li.h ./ber.h thread.h packet_capture.h
forgery.o: forgery.h context.h socket.h address.h pdu.h exception.h flow.h
forgery.o: reaper.h thread.h base_context.h manager.h observer.h
forgery.o: dns_protocol.h dns.h serial.h protocol.h hexdump.h udp.h tcp.h
forgery.o: ip.h
http.o: address.h pdu.h socket.h exception.h http.h context.h flow.h reaper.h
http.o: thread.h base_context.h manager.h observer.h dns_protocol.h serial.h
http.o: protocol.h
icmp.o: icmp.h context.h socket.h address.h pdu.h exception.h flow.h reaper.h
icmp.o: thread.h base_context.h manager.h observer.h dns_protocol.h
ip.o: ip.h context.h socket.h address.h pdu.h exception.h flow.h reaper.h
ip.o: thread.h base_context.h manager.h observer.h dns_protocol.h tcp.h
ip.o: serial.h protocol.h udp.h icmp.h
nhis11.o: nhis11.h socket.h thread.h monitor.h
nhis11_rcvr.o: monitor.h socket.h nhis11.h thread.h packet_capture.h
readline.o: readline.h
reaper.o: reaper.h thread.h
resource_manager.o: resource.h thread.h specification.h
sender.o: sender.h management.h socket.h thread.h nhis11.h monitor.h
sender.o: etsi_li.h ./ber.h parameters.h
snort_alert.o: socket.h snort_alert.h resource.h thread.h specification.h
snort_alert.o: delivery.h sender.h management.h nhis11.h monitor.h etsi_li.h
snort_alert.o: ./ber.h parameters.h capture.h packet_capture.h
snort_alert.o: packet_consumer.h
socket.o: socket.h
tcp.o: tcp.h context.h socket.h address.h pdu.h exception.h flow.h reaper.h
tcp.o: thread.h base_context.h manager.h observer.h dns_protocol.h serial.h
tcp.o: protocol.h http.h unrecognised.h forgery.h
udp.o: udp.h context.h socket.h address.h pdu.h exception.h flow.h reaper.h
udp.o: thread.h base_context.h manager.h observer.h dns_protocol.h
udp.o: unrecognised.h serial.h protocol.h dns.h
unrecognised.o: unrecognised.h context.h socket.h address.h pdu.h exception.h
unrecognised.o: flow.h reaper.h thread.h base_context.h manager.h observer.h
unrecognised.o: dns_protocol.h serial.h protocol.h
xml.o: xml.h
