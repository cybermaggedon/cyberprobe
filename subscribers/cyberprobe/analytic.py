
import pulsar
import os
import sys
import uuid

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

