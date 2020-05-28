
bin_SCRIPTS = cybermon-alert cybermon-elasticsearch cybermon-gaffer	\
	cybermon-monitor cybermon-bigquery cybermon-cassandra		\
	cybermon-dump cybermon-geoip

EXTRA_DIST = cybermon-alert cybermon-elasticsearch cybermon-gaffer	\
	cybermon-monitor cybermon-bigquery cybermon-cassandra		\
	cybermon-dump cybermon-geoip

cyberprobe_PYTHON = cyberprobe/analytic.py cyberprobe/cyberprobe_pb2.py
cyberprobedir = $(pythondir)/cyberprobe

cyberprobe/cyberprobe_pb2.py: $(srcdir)/../protos/cyberprobe.proto
	protoc -I=$(srcdir)/../protos --python_out=cyberprobe/ $(srcdir)/../protos/cyberprobe.proto 

