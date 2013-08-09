
CXXFLAGS += -I. -O6

CYBERPROBE_OBJECTS=cyberprobe.o socket.o nhis11.o etsi_li.o \
	resource_manager.o sender.o delivery.o xml.o ber.o capture.o config.o \
	control.o snort_alert.o

all: cyberprobe nhis11_rcvr etsi_rcvr

cyberprobe: ${CYBERPROBE_OBJECTS}
	${CXX} ${CXXFLAGS} ${CYBERPROBE_OBJECTS} -o $@ -lpcap -lpthread -lexpat

nhis11_rcvr: nhis11_rcvr.o nhis11.o socket.o
	${CXX} ${CXXFLAGS} nhis11_rcvr.o nhis11.o socket.o -o $@ -lpthread \
	  -lpcap

etsi_rcvr: etsi_rcvr.o etsi_li.o socket.o ber.o
	${CXX} ${CXXFLAGS} etsi_rcvr.o etsi_li.o socket.o ber.o -o $@ \
	  -lpthread -lpcap

depend:
	makedepend -Y. *.C

# DO NOT DELETE

ber.o: ./ber.h ./socket.h
capture.o: capture.h packet_capture.h packet_consumer.h thread.h
config.o: config.h resource.h thread.h specification.h delivery.h sender.h
config.o: management.h ./socket.h nhis11.h monitor.h etsi_li.h ./ber.h
config.o: parameters.h capture.h packet_capture.h packet_consumer.h xml.h
config.o: interface.h target.h endpoint.h parameter.h snort_alert.h control.h
control.o: control.h ./socket.h thread.h management.h specification.h
control.o: resource.h
cyberprobe.o: config.h resource.h thread.h specification.h delivery.h
cyberprobe.o: sender.h management.h ./socket.h nhis11.h monitor.h etsi_li.h
cyberprobe.o: ./ber.h parameters.h capture.h packet_capture.h
cyberprobe.o: packet_consumer.h
delivery.o: delivery.h sender.h management.h ./socket.h thread.h nhis11.h
delivery.o: monitor.h etsi_li.h ./ber.h parameters.h capture.h
delivery.o: packet_capture.h packet_consumer.h
etsi_li.o: etsi_li.h ./socket.h ./ber.h thread.h monitor.h
etsi_rcvr.o: monitor.h ./socket.h etsi_li.h ./ber.h thread.h packet_capture.h
nhis11.o: nhis11.h ./socket.h thread.h monitor.h
nhis11_rcvr.o: monitor.h ./socket.h nhis11.h thread.h packet_capture.h
resource_manager.o: resource.h thread.h specification.h
sender.o: sender.h management.h ./socket.h thread.h nhis11.h monitor.h
sender.o: etsi_li.h ./ber.h parameters.h
snort_alert.o: ./socket.h snort_alert.h resource.h thread.h specification.h
snort_alert.o: delivery.h sender.h management.h nhis11.h monitor.h etsi_li.h
snort_alert.o: ./ber.h parameters.h capture.h packet_capture.h
snort_alert.o: packet_consumer.h
socket.o: ./socket.h
xml.o: xml.h
