
bin_SCRIPTS = evs-alert evs-elasticsearch evs-gaffer	\
	evs-monitor evs-cassandra evs-dump		\
	evs-geoip

EXTRA_DIST = evs-alert evs-elasticsearch evs-gaffer	\
	evs-monitor evs-cassandra evs-dump		\
	evs-geoip

cyberprobe_PYTHON = cyberprobe/analytic.py cyberprobe/cyberprobe_pb2.py
cyberprobedir = $(pythondir)/cyberprobe

BUILT_SOURCES = cyberprobe/cyberprobe_pb2.py

cyberprobe/cyberprobe_pb2.py: $(srcdir)/../protos/cyberprobe.proto
	protoc -I=$(srcdir)/../protos --python_out=cyberprobe/ $(srcdir)/../protos/cyberprobe.proto 

