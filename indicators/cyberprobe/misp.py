
import sys
import json
import pymisp
import re
from cyberprobe.indicators import Indicator, Indicators, Descriptor
from cyberprobe.logictree import Match, And, Or, Not

class MispParser:

    def __init__(self, dict):
        self.category = ["Network activity"]
        self.type = ["hostname", "ip-src", "ip-dst", "ip-src|port",
                     "ip-dest|port", "domain", "domain|ip",
                     "url", "uri"]
        self.to_ids = True
        for v in dict:
            setattr(self, v, dict[v])
        self.misp = pymisp.ExpandedPyMISP(self.url, self.token)

    @classmethod
    def from_config(cls, path):
        config = json.load(open(path))
        return cls(config)

    def chunked(self, x, n=5):
        for i in range(0, len(x), n):
            yield x[i:i+n]

    def get_events(self):

        evs = []
        page=1
        sys.stderr.write("Page: ")
        sys.stderr.flush()

        while True:
            sys.stderr.write(f"{page} ")
            sys.stderr.flush()
            events = self.misp.search("events", limit=25, page=page,
                                      metadata=True)
            if len(events) == 0: break
            evs.extend([ev['Event'] for ev in events])
            page=page+1

        sys.stderr.write('\n')
        return evs

    def get_attributes(self, evids):

        page=1
        while True:

            res = self.misp.search("attributes", eventid=evids,
                                   category=self.category,
                                   type_attribute=self.type,
                                   to_ids=self.to_ids, page=page, limit=15000)

            if "Attribute" not in res:
                raise RuntimeError("No Attribute result?!")

            if len(res["Attribute"]) == 0:
                break

            for attr in res["Attribute"]:
                yield attr

            page += 1

    def to_indicators(self, limit=10000000):

        sys.stderr.write("Getting event IDs...\n")
        events = self.get_events()
        sys.stderr.write("Done.\n")
        sys.stderr.write(f'Got {len(events)} events.\n')

        count = 0

        blip=25000
        skip=blip

        sys.stderr.write("Getting attributes...\n")

        for ev in events:

            attrs = self.get_attributes([ev["uuid"]])

            for attr in attrs:

                while count >= blip:
                    sys.stderr.write(f"{blip} ")
                    sys.stderr.flush()
                    blip += skip

                info = attr["Event"]["info"]
                comment = attr["comment"]
                category = attr["category"]
                type = attr["type"]
                value = attr["value"]
                uuid = attr["uuid"]
                if "event_creator_email" in ev:
                    author = ev["event_creator_email"]
                else:
                    author = ev["Orgc"]["name"]

                stype = None

                if type == "domain" or type == "hostname":

                    bval = Match("hostname", value)
                    sval = value
                    stype = "hostname"

                elif type == "url" or type == "uri":

                    if value.startswith("http://") or value.startswith("https://"):

                        bval = Match("url", value)
                        sval = value
                        stype = "url"

                    else:

                        sval = "https://" + value
                        stype = "url"
                        bval = Or([
                            Match("url", "http://" + value),
                            Match("url", "https://" + value)
                        ])

                elif type == "ip-src" or type == "ip-dst":

                    if re.match(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$",
                                value) == None:

                        if type == "ip-src":
                            bval = Match("ipv6.src", value)
                        else:
                            bval = Match("ipv6.dest", value)
                        sval = value
                        stype = "ipv6"

                    else:

                        if type == "ip-src":
                            bval = Match("ipv4.src", value)
                        else:
                            bval = Match("ipv4.dest", value)
                        sval = value
                        stype = "ipv4"

                if stype != None:

                    des = Descriptor(category="exploit",
                                     description=info,
                                     author=author,
                                     source=self.url, prob=1.0,
                                     type=stype, value=sval)
                    ii = Indicator(des, id=uuid)
                    ii.value = bval

                    yield ii

                    count += 1
                    if count >= limit:
                        break

        sys.stderr.write("\nDone.\n")
        sys.stderr.write(f"{count} indicators.\n")


