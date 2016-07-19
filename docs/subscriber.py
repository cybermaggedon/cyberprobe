#!/usr/bin/env python

import json
import time
import base64
import hmac
import Crypto.Hash.SHA256 as SHA256
import requests
import Crypto.Signature.PKCS1_v1_5 as PKCS1_v1_5
import Crypto.PublicKey.RSA as RSA
import sys

s = requests.Session()

private = json.loads(open("private.json", "r").read())
email = private["client_email"]
private = private["private_key"]
private = RSA.importKey(private)

header = { 'alg': 'RS256', 'typ': 'JWT'}
header = json.dumps(header)
header = base64.urlsafe_b64encode(header)

# Create an PKCS1_v1_5 object
signer = PKCS1_v1_5.new(private)

cs = {
    "iss": email,
    "scope": "https://www.googleapis.com/auth/cloud-platform",
    "aud": "https://www.googleapis.com/oauth2/v4/token",
    "exp": int(time.time() + 3600),
    "iat": int(time.time())
    }
cs = json.dumps(cs)
cs = base64.b64encode(cs)

msg_hash = SHA256.new(header + "." + cs)
signature = signer.sign(msg_hash)
signature = base64.urlsafe_b64encode(signature)

input = header + "." + cs

jwt ="%s.%s.%s" % (header, cs, signature)

gt = "urn:ietf:params:oauth:grant-type:jwt-bearer"
data={'grant_type': gt, 'assertion': jwt}

print "Authenticate..."
uri = "https://www.googleapis.com/oauth2/v4/token"
r = s.post(uri, data=data)
response = r.json()
if r.status_code != 200:
    print "Failed"
    print r.text
    sys.exit(0)
    
token = response["access_token"]
auth = "%s %s" % (response["token_type"], response["access_token"])

project = "INSERT_PROJECT"
topic = "cyberprobe"
subs = "mysubs"

# ------------------------------------------------------------

subscription = {
    "topic": "projects/%s/topics/%s" % (project, topic)
}
subscription=json.dumps(subscription)

uri = "https://pubsub.googleapis.com/v1/projects/%s/subscriptions/%s" % \
	(project, subs)

print "Create subscription..."
r = s.put(uri, headers={"Authorization": auth}, data=subscription)

if r.status_code != 200 and r.status_code != 409:
    print "Failed"
    print r.text
    sys.exit(0)

# ------------------------------------------------------------

while True:

    body = {
        "returnImmediately": False,
        "maxMessages": 100
    }
    body=json.dumps(body)

    uri = "https://pubsub.googleapis.com/v1/projects/%s/subscriptions/%s:pull" % \
	  (project, subs)
    
    r = s.post(uri, headers={"Authorization": auth}, data=body)
    if r.status_code != 200:
        print "Failed"
        print r.text
        sys.exit(0)

    ids = []
    obj = r.json()
    if obj.has_key("receivedMessages"):
        rm = obj["receivedMessages"]
        for v in rm:
            ids.append(v["ackId"])
            msg = json.loads(base64.b64decode(v["message"]["data"]))
            print msg["action"]

        body = {
            "ackIds": ids
        }
        body = json.dumps(body)
        uri = "https://pubsub.googleapis.com/v1/projects/%s/subscriptions/%s:acknowledge" % \
	      (project, subs)

        r = s.post(uri, headers={"Authorization": auth}, data=body)
        if r.status_code != 200:
            print "Failed"
            print r.text
            sys.exit(0)

sys.exit(0)

# ------------------------------------------------------------

uri = "https://pubsub.googleapis.com/v1/projects/%s/subscriptions/%s" % \
	(project, subs)

print "Delete subscription..."
r = s.delete(uri, headers={"Authorization": auth})
if r.status_code != 200:
    print "Failed"
    print r.text
    sys.exit(0)

# ------------------------------------------------------------

