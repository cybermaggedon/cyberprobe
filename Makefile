
CXXFLAGS += -I. -O6

CYBERPROBE_OBJECTS=cyberprobe.o socket.o nhis11.o etsi_li.o \
	resource_manager.o sender.o delivery.o xml.o ber.o capture.o config.o \
	control.o snort_alert.o

CYBERMON_OBJECTS=cybermon.o analyser.o etsi_li.o socket.o ber.o context.o ip.o \
	tcp.o udp.o address.o

ANALYSE_OBJECTS=analyse.o analyser.o context.o ip.o socket.o tcp.o udp.o \
	address.o

all: cyberprobe cybermon nhis11_rcvr etsi_rcvr analyse

cyberprobe: ${CYBERPROBE_OBJECTS}
	${CXX} ${CXXFLAGS} ${CYBERPROBE_OBJECTS} -o $@ -lpcap -lpthread -lexpat

cybermon: ${CYBERMON_OBJECTS}
	${CXX} ${CXXFLAGS} ${CYBERMON_OBJECTS} -o $@ -lpcap -lpthread -lexpat

analyse: ${ANALYSE_OBJECTS}
	${CXX} ${CXXFLAGS} ${ANALYSE_OBJECTS} -o $@ -lpcap -lpthread -lexpat

nhis11_rcvr: nhis11_rcvr.o nhis11.o socket.o
	${CXX} ${CXXFLAGS} nhis11_rcvr.o nhis11.o socket.o -o $@ -lpthread \
	  -lpcap

etsi_rcvr: etsi_rcvr.o etsi_li.o socket.o ber.o
	${CXX} ${CXXFLAGS} etsi_rcvr.o etsi_li.o socket.o ber.o -o $@ \
	  -lpthread -lpcap

depend:
	makedepend -Y. *.C

# DO NOT DELETE

address.o: socket.h address.h pdu.h
analyse.o: packet_capture.h analyser.h thread.h pdu.h context.h socket.h
analyse.o: address.h flow.h exception.h hexdump.h
analyser.o: thread.h context.h socket.h pdu.h address.h flow.h exception.h
analyser.o: analyser.h ip.h
ber.o: ./ber.h socket.h
capture.o: capture.h packet_capture.h packet_consumer.h thread.h
config.o: config.h resource.h thread.h specification.h delivery.h sender.h
config.o: management.h socket.h nhis11.h monitor.h etsi_li.h ./ber.h
config.o: parameters.h capture.h packet_capture.h packet_consumer.h xml.h
config.o: interface.h target.h endpoint.h parameter.h snort_alert.h control.h
context.o: socket.h context.h thread.h pdu.h address.h flow.h exception.h
control.o: control.h socket.h thread.h management.h specification.h
control.o: resource.h
cybermon.o: analyser.h thread.h pdu.h context.h socket.h address.h flow.h
cybermon.o: exception.h monitor.h etsi_li.h ./ber.h packet_capture.h
cybermon.o: hexdump.h
cyberprobe.o: config.h resource.h thread.h specification.h delivery.h
cyberprobe.o: sender.h management.h socket.h nhis11.h monitor.h etsi_li.h
cyberprobe.o: ./ber.h parameters.h capture.h packet_capture.h
cyberprobe.o: packet_consumer.h
delivery.o: delivery.h sender.h management.h socket.h thread.h nhis11.h
delivery.o: monitor.h etsi_li.h ./ber.h parameters.h capture.h
delivery.o: packet_capture.h packet_consumer.h
etsi_li.o: etsi_li.h socket.h ./ber.h thread.h monitor.h
etsi_rcvr.o: monitor.h socket.h etsi_li.h ./ber.h thread.h packet_capture.h
ip.o: ip.h context.h socket.h thread.h pdu.h address.h flow.h exception.h
ip.o: analyser.h tcp.h udp.h
nhis11.o: nhis11.h socket.h thread.h monitor.h
nhis11_rcvr.o: monitor.h socket.h nhis11.h thread.h packet_capture.h
resource_manager.o: resource.h thread.h specification.h
sender.o: sender.h management.h socket.h thread.h nhis11.h monitor.h
sender.o: etsi_li.h ./ber.h parameters.h
snort_alert.o: socket.h snort_alert.h resource.h thread.h specification.h
snort_alert.o: delivery.h sender.h management.h nhis11.h monitor.h etsi_li.h
snort_alert.o: ./ber.h parameters.h capture.h packet_capture.h
snort_alert.o: packet_consumer.h
socket.o: socket.h
tcp.o: tcp.h context.h socket.h thread.h pdu.h address.h flow.h exception.h
tcp.o: analyser.h
udp.o: udp.h context.h socket.h thread.h pdu.h address.h flow.h exception.h
udp.o: analyser.h
xml.o: xml.h
