
from cyberprobe.fsm import Fsm, FsmState, FsmCollection
import cyberprobe.indicators as ind

class Detector:

    def __init__(self):
        self.iocs = None
        self.fsc = None

    def load(self, obj):
        self.iocs = ind.load(obj)
        self.fsc = FsmCollection.load_from(self.iocs)

    def load_fsc(self, iocs, fsc):
        self.iocs = iocs
        self.fsc = fsc

    def add_indicator(self, obj, ind):
        if "indicators" not in obj:
            obj["indicators"] = []
        obj["indicators"].append(ind)

    def check_addresses(self, obj):

        for v in obj["src"]:
            if v.startswith("ipv4:"):
                self.fsc.update(('ipv4', v[5:]))
                self.fsc.update(('ipv4.src', v[5:]))
            if v.startswith("ipv6:"):
                self.fsc.update(('ipv6', v[5:]))
                self.fsc.update(('ipv6.src', v[5:]))
            if v.startswith("tcp:"):
                self.fsc.update(('tcp', v[4:]))
                self.fsc.update(('tcp.src', v[4:]))
            if v.startswith("udp:"):
                self.fsc.update(('udp', v[4:]))
                self.fsc.update(('udp.dest', v[4:]))

        for v in obj["dest"]:
            if v.startswith("ipv4:"):
                self.fsc.update(('ipv4', v[5:]))
                self.fsc.update(('ipv4.dest', v[5:]))
            if v.startswith("ipv6:"):
                self.fsc.update(('ipv6', v[5:]))
                self.fsc.update(('ipv6.dest', v[5:]))
            if v.startswith("tcp:"):
                self.fsc.update(('tcp', v[4:]))
                self.fsc.update(('tcp.dest', v[4:]))
            if v.startswith("udp:"):
                self.fsc.update(('udp', v[4:]))
                self.fsc.update(('udp.dest', v[4:]))

    def check_dns(self, obj):

        hosts = set()

        if "dns_message" in obj and "query" in obj["dns_message"]:
            for v in obj["dns_message"]["query"]:
                if "name" in v:
                    hosts.add(v["name"])

        if "dns_message" in obj and "answer" in obj["dns_message"]:
            for v in obj["dns_message"]["answer"]:
                if "name" in v:
                    hosts.add(v["name"])

        for v in hosts:
            self.fsc.update(('hostname', v))

    def check_url(self, obj):

        if "url" in obj:
            self.fsc.update(('url', obj["url"]))

    def check_email(self, obj):

        emails = set()
        if "smtp_data" in obj and "from" in obj["smtp_data"]:
            emails.add(obj["smtp_data"]["from"])
        if "smtp_data" in obj and "to" in obj["smtp_data"]:
            for v in obj["smtp_data"]["to"]:
                emails.add(v)

        for v in emails:
            self.fsc.update(('email', v))

    def check_hits(self, obj):
        inds = self.fsc.get_hits()
        for ind in inds:
            self.add_indicator(obj, ind.descriptor.dump())

    def detect(self, event):

        self.fsc.init_state()
        self.check_addresses(event)
        self.check_dns(event)
        self.check_url(event)
        self.check_email(event)
        self.fsc.update(('end', ''))

        self.check_hits(event)

