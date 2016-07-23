#!/usr/bin/env python

binding = "tcp://localhost:5555"
gaffer = "http://gaffer:8080/example-rest/v1"

############################################################################

import zmq
import json
import uuid
import sys

############################################################################

def init():
    pass

def output(obs):
    print(json.dumps(obs))

############################################################################

def handle(msg):

    # FIXME: Make a UUID up-stream.  How are we supposed to correlate things??
    id = str(uuid.uuid1())

    observation = {
        "id": id,
        "action": msg["action"],
        "device": msg["device"],
        "time": msg["time"]
        }

    if msg.has_key("method"):
        observation["method"] = msg["method"]
    if msg.has_key("url"):
        observation["url"] = msg["url"]
    if msg.has_key("command"):
        observation["command"] = msg["command"]
    if msg.has_key("status"):
        observation["status"] = msg["status"]
    if msg.has_key("text"):
        observation["text"] = msg["text"]
    if msg.has_key("payload"):
        pass
    if msg.has_key("body"):
        pass
    if msg.has_key("from"):
        observation["from"] = msg["from"]
    if msg.has_key("to"):
        observation["to"] = msg["to"]
    if msg.has_key("header"):
        observation["header"] = msg["header"]
    if msg.has_key("type"):
        observation["type"] = msg["type"]
    if msg.has_key("queries"):
        observation["queries"] = msg["queries"]
    if msg.has_key("answers"):
        observation["answers"] = msg["answers"]

    observation["src"] = {}
    observation["dest"] = {}

    if msg.has_key("src"):
        for v in msg["src"]:
            if v.find(":") < 0:
                cls = v
                addr = ""
            else:
                cls = v[0:v.find(":")]
                addr = v[v.find(":") + 1:]

            if not observation["src"].has_key(cls):
                observation["src"][cls] = []

            observation["src"][cls].append(addr)

    if msg.has_key("dest"):
        for v in msg["dest"]:
            if v.find(":") < 0:
                cls = v
                addr = ""
            else:
                cls = v[0:v.find(":")]
                addr = v[v.find(":") + 1:]

            if not observation["dest"].has_key(cls):
                observation["dest"][cls] = []

            observation["dest"][cls].append(addr)

    output(observation)

############################################################################

ctxt = zmq.Context()
skt = ctxt.socket(zmq.SUB)
skt.connect(binding)
skt.setsockopt(zmq.SUBSCRIBE, "")

init()

while True:
    msg = skt.recv()
    handle(json.loads(msg))

