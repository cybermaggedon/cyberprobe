# Cyberprobe

The full documentation is at https://cybermaggedon.github.io/cyberprobe-docs/

## Summary

Cyberprobe is a network packet inspection toolkit (Deep Packet Inspection)
for real-time monitoring of networks. This has applications in network
monitoring, intrusion detection, forensic analysis, and as a defensive
platform. Cyberprobe packet inspection works on physical networks, and also
in cloud VPCs. There are features that allow cloud-scale deployments.

This is not a single, monolithic intrusion detection toolkit which does
everything you want straight out of the box. If that’s what you need, I
would suggest you look elsewhere. Instead, Cyberprobe is a set of flexible
components which can combined in many ways to manage a wide variety of
packet inspection tasks. If you want to build custom network analytics there
are many interfaces that make this straightforward.

The project maintains a number of components, including:

- cyberprobe, which collects data packets and forwards them a network stream
  protocol in real time. Packet collection can be target with IP addresses,
  CIDR ranges or full-take.  Collected packets are tagged with a device
  identifier. cyberprobe can be integrated with Snort to allow dynamic
  targeting of IP addresses in response to a Snort rule hitting.
- cybermon, which receives collected packet streams, performs stateful
  processing and creates a stream of observations describing network
  events. The events can be consumed in many different ways e.g. the events
  can be delivered to a pub/sub system, or presented to a gRPC service. The
  event handling is implemented as a function written in Lua, so you can add
  your own custom event handling.
- a set of subscribers which can be used to do things with the captured data
  e.g. store to ElasticSearch, BigQuery or Gaffer.

## Cyberprobe

The probe, cyberprobe has the following features:

- Can be tasked to collect packets from an interface and forward any which
  match a configurable address list. The address list can be individual IP
  addresses, CIDR ranges, or collect-all tasking (‘0.0.0.0/0’).
- Can be configured to receive Snort alerts. In this configuration, when an
  alert is received from Snort, the IP source address associated with the
  alert is dynamically targeted for a configurable period of time. This is
  useful for e.g. collecting data from any network actor who triggers a snort
  rule and is thus identified as a potential attacker.
- Can optionally offer a management API which allows remote interrogation of
  the state, and alteration of the configuration. This allows dynamic
  alteration of the targeting map, and integration with other systems.
- Can be configured to deliver on one of two standard stream protocols.
- Can insert a packet collection delay line of configurable duration. This
  can be useful e.g. with snort alert triggering to make sure all packets
  which trigger an alert are collected.

## Cybermon

The monitor tool, cybermon has the following features:

- Analyses packets delivered in the ETSI stream protocol from one or more
  cyberprobe instances.
- Decodes a number of packet protocols to detect network events, which are
  delivered to your configuration in near-real-time.
- Decoded information is made available to user-configurable logic (written
  in Lua) to define how the decoded data is handled. Sample configuration
  files are provided to deliver to RabbitMQ in JSON, a gRPC endpoint, and
  deliver to a redis queue.
- Packet forgery techniques are included, which allow resetting TCP
  connections, and forging DNS responses. This can be invoked from your Lua
  configuration.
- Supports IP, TCP, UDP, ICMP, HTTP, DNS, SMTP, FTP, TLS and more.  The code
  is targeted at the Linux platform, although it is generic enough to be
  applicable to other UN*X-like platforms.

## Subscribers

The event stream from cybermon can be presented to RabbitMQ in a JSON form,
which can then be delivered to further analytics:
- cybermon-alert reports indicator hits in events to standard output.
- cybermon-bigquery loads events into GCP BigQuery.
- cybermon-cassandra loads events into Cassandra.
- cybermon-detector studies events for the presence of indicators. Events are
  annotated with indicator hits of any are observed.
- cybermon-dump dumps raw event JSON to standard output.
- cybermon-elasticsearch loads events into ElasticSearch.
- cybermon-gaffer loads network information into Gaffer (a graph database).
- cybermon-geoip looks up IP addresses in GeoIP and annotates events with
  location information.
- cybermon-monitor outputs event information to standard output.

## Scaling

The architecture has support for AWS Traffic Mirroring, and supports
cloud-scale deployments:

- Multiple cyberprobe instances can load-share across multiple cybermon
  instances behind a load-balancer.

- The event stream from cybermon can be delivered to a pub/sub system to
  distribute load and permit scale-up.

## More information

The easiest way to learn about the software is to follow our Quick Start
tutorial.
