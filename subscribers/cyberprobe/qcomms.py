
import pika
import os
import sys
import uuid

def subscribe(binding, handle, output=None):

    if output != None:
        outq = Publisher(routing_key=output)
    else:
        outq = None

    def output(body):
        if outq != None:
            outq.publish(body)
        
    def cb(ch, m, props, body):
        handle(body, output)

    queue=str(uuid.uuid4())
    
    s = Subscriber(queue=queue, routing_key=binding, durable=False,
                   auto_delete=True)
    s.consume(cb)

class Subscriber:
    def __init__(self, broker=None, queue=None, routing_key=None,
                 durable=True, auto_delete=False, exclusive=False):

        if broker == None:
            broker=os.getenv("AMQP_BROKER", "localhost")

        exchange=os.getenv("AMQP_INPUT_EXCHANGE", "amq.topic")

        if queue == None:
            queue=os.getenv("AMQP_INPUT_QUEUE", "default")

        if routing_key == None:
            routing_key=os.getenv("AMQP_INPUT_ROUTING_KEY", "default")

        self.broker = broker
        self.exchange = exchange
        self.queue = queue
        self.routing_key=routing_key

        self.connection = None
        self.channel = None
        self.connect()

        self.channel.exchange_declare(exchange=self.exchange,
                                      exchange_type='topic',
                                      durable=True)
        self.channel.queue_declare(queue=queue,
                                   auto_delete=auto_delete,
                                   exclusive=exclusive,
                                   durable=durable)
        self.channel.queue_bind(exchange=exchange, queue=queue,
                                routing_key=routing_key)

    def consume(self, cb):
            self.channel.basic_consume(on_message_callback=cb,
                                       queue=self.queue, auto_ack=True)
            self.channel.start_consuming()

    def connect(self):

        self.close()

        conn = pika.BlockingConnection(pika.ConnectionParameters(self.broker))
        self.connection = conn
        self.channel = self.connection.channel()

    def close(self):

        if self.channel != None:
            try:
                self.channel.close()
            except Exception as e:
                pass
            self.channel = None

        if self.connection != None:
            try:
                self.connection.close()
            except Exception as e:
                pass
            self.connection = None

class Publisher:
    def __init__(self, broker=None, routing_key=None):

        if broker == None:
            broker=os.getenv("AMQP_BROKER", "localhost")

        exchange=os.getenv("AMQP_OUTPUT_EXCHANGE", "amq.topic")

        if routing_key == None:
            routing_key=os.getenv("AMQP_OUTPUT_ROUTING_KEY", "default")

        self.broker = broker
        self.exchange = exchange
        self.routing_key = routing_key

        self.connection = None
        self.channel = None
        self.connect()

    def publish(self, body, routing_key=None):

        if routing_key==None:
            routing_key = self.routing_key
            
        self.channel.basic_publish(exchange=self.exchange,
                                   routing_key=routing_key,
                                   body=body)

    def connect(self):

        self.close()
        conn = pika.BlockingConnection(pika.ConnectionParameters(self.broker))
        self.connection = conn
        self.channel = self.connection.channel()

    def close(self):

        if self.channel != None:
            try:
                self.channel.close()
            except Exception as e:
                pass
            self.channel = None
                      
        if self.connection != None:
            try:
                self.connection.close()
            except Exception as e:
                pass
            self.Connection = None
