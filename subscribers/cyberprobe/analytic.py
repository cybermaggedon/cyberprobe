
import pulsar
import os
import sys
import uuid
import cyberprobe.cyberprobe_pb2 as pb

def subscribe(binding, handle, output=None):

    broker = os.getenv("PULSAR_BROKER", "pulsar://localhost:6650")

    in_topic = f"persistent://public/default/{binding}"
    out_topic = f"persistent://public/default/{output}"

    if output != None:
        outq = Producer(broker, out_topic)
    else:
        outq = None

    def output(msg, properties=None):
        if outq != None:
            outq.publish(msg, properties)
        
    def cb(msg):
        handle(msg, output)

    subs = str(uuid.uuid4())
    
    c = Consumer(subs, broker, in_topic)
    c.consume(cb)

class Analytic:
    def __init__(self, binding, outputs=[]):
        
        broker = os.getenv("PULSAR_BROKER", "pulsar://localhost:6650")

        in_topic = f"persistent://public/default/{binding}"
        out_topics = [f"persistent://public/default/{v}" for v in outputs]
        self.outqs = [Producer(broker, v) for v in out_topics]

        subs = str(uuid.uuid4())
    
        self.cons = Consumer(subs, broker, in_topic)

    def run(self):
        self.cons.consume(self.handle)

    def handle(self, msg):
        pass

    def output(self, msg, properties=None):
        for q in self.outqs:
            q.publish(msg, properties)

class EventAnalytic(Analytic):

    def event(self, ev, properties):
        pass
    
    def handle(self, msg):
        try:
            ev = pb.Event()
            ev.ParseFromString(msg.data())
            self.event(ev, msg.properties())
        except Exception as e:
            print("Exception:", e)

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
                cb(msg)
            except Exception as e:
                pass

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

