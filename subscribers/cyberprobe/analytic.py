
import pulsar
from prometheus_client import start_http_server
from prometheus_client import Counter, Summary, Histogram, Info
import os
import sys
import uuid
import cyberprobe.cyberprobe_pb2 as pb

request_time=Summary('event_processing_time', 'Time spent processing event')
event_size=Histogram('event_size', 'Size of event message',
                     buckets=[25, 50, 100, 250, 500, 1000, 2500, 5000,
                              10000, 25000, 50000, 100000, 250000, 500000,
                              1000000, 2500000])
events=Counter('events_total', 'Events processed total', ['state'])
info=Info('configuration', 'Configuration settings')

class Analytic:
    def __init__(self, binding, outputs=[]):

        metrication = os.getenv("METRICS_PORT")
        if metrication != None:
            port = int(metrication)
            start_http_server(port)
            print(f"Metrics served on port {port}")

        broker = os.getenv("PULSAR_BROKER", "pulsar://localhost:6650")

        in_topic = f"persistent://public/default/{binding}"
        out_topics = [f"persistent://public/default/{v}" for v in outputs]
        self.outqs = [Producer(broker, v) for v in out_topics]

        subs = str(uuid.uuid4())

        info.info({
            'input_topic': in_topic,
            'output_topics': " ".join(out_topics),
            'broker': broker,
            'subscriber': subs,
        })
    
        self.cons = Consumer(subs, broker, in_topic)

    def run(self):
        self.cons.consume(self.dohandle)

    def dohandle(self, msg):
        try:
            with request_time.time():
                event_size.observe(len(msg.data()))
                self.handle(msg)
                events.labels('success').inc()
        except Exception as e:
            print("Exception:", e)
            events.labels('failure').inc()

    def handle(self, msg):
        pass

    def output(self, msg, properties=None):
        for q in self.outqs:
            q.publish(msg, properties)

class EventAnalytic(Analytic):

    def event(self, ev, properties):
        pass
    
    def handle(self, msg):
        ev = pb.Event()
        ev.ParseFromString(msg.data())
        self.event(ev, msg.properties())

    def output_event(self, ev, properties=None):
        data = ev.SerializeToString()
        self.output(data, properties)

class Consumer:

    def __init__(self, subs, broker=None, topic=None):

        if broker == None:
            broker=os.getenv("PULSAR_BROKER", "pulsar://localhost:6650")

        if topic == None:
            routing_key=os.getenv("PULSAR_TOPIC")

        if subs == None:
            subs = os.getenv("PULSAR_SUBSCRIPTION")

        self.client = pulsar.Client(broker)
        self.consumer = self.client.subscribe(topic, subs)

    def consume(self, cb):
        while True:
            try:
                msg = self.consumer.receive(200)
            except Exception as e:
                # Pulsar Timeout.  Shame the type is 'Exception' so can't be
                # distinguished from other events very easily.
                continue
            cb(msg)

    def close(self):
        self.consumer.unsubscribe()
        self.client.close()
        
class Producer:
    def __init__(self, broker=None, topic=None):

        if broker == None:
            broker=os.getenv("PULSAR_BROKER", "pulsar://localhost:6650")

        if topic == None:
            routing_key=os.getenv("PULSAR_PRODUCER_TOPIC")

        self.client = pulsar.Client(broker)
        self.producer = self.client.create_producer(topic)

    def publish(self, content, properties=None):
        self.producer.send(content, properties)

    def close(self):
        self.client.close()

