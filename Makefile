
CXXFLAGS += -I. -O6
OBJECTS=cyberprobe.o socket.o nhis11.o etsi_li.o resource_manager.o sender.o  \
	delivery.o xml.o ber.o capture.o config.o control.o snort_alert.o

all: cyberprobe nhis11_rcvr etsi_rcvr

cyberprobe: ${OBJECTS}
	${CXX} ${CXXFLAGS} ${OBJECTS} -o $@ -lpcap -lpthread -lexpat

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
capture.o: capture.h packet_capture.h delivery.h sender.h thread.h nhis11.h
capture.o: ./socket.h packet.h etsi_li.h ./ber.h parameters.h targeting.h
config.o: config.h resource.h thread.h specification.h delivery.h sender.h
config.o: nhis11.h ./socket.h packet.h etsi_li.h ./ber.h parameters.h
config.o: targeting.h xml.h interface.h capture.h packet_capture.h target.h
config.o: endpoint.h parameter.h snort_alert.h control.h
control.o: control.h ./socket.h thread.h targeting.h sender.h nhis11.h
control.o: packet.h etsi_li.h ./ber.h parameters.h specification.h resource.h
cyberprobe.o: nhis11.h ./socket.h thread.h packet.h packet_capture.h
cyberprobe.o: resource.h specification.h delivery.h sender.h etsi_li.h
cyberprobe.o: ./ber.h parameters.h targeting.h xml.h target.h capture.h
cyberprobe.o: interface.h endpoint.h config.h parameter.h
delivery.o: delivery.h sender.h thread.h nhis11.h ./socket.h packet.h
delivery.o: etsi_li.h ./ber.h parameters.h targeting.h
etsi_li.o: etsi_li.h ./socket.h ./ber.h thread.h packet.h
etsi_rcvr.o: packet.h ./socket.h etsi_li.h ./ber.h thread.h packet_capture.h
nhis11.o: nhis11.h ./socket.h thread.h packet.h
nhis11_rcvr.o: packet.h ./socket.h nhis11.h thread.h packet_capture.h
resource_manager.o: resource.h thread.h specification.h
sender.o: sender.h thread.h nhis11.h ./socket.h packet.h etsi_li.h ./ber.h
sender.o: parameters.h
snort_alert.o: ./socket.h snort_alert.h resource.h thread.h specification.h
snort_alert.o: delivery.h sender.h nhis11.h packet.h etsi_li.h ./ber.h
snort_alert.o: parameters.h targeting.h
socket.o: ./socket.h
xml.o: xml.h
