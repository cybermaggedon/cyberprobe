
import datetime

############################################################################
# Timezone class, representing GMT.
############################################################################
class GMT(datetime.tzinfo):
    """GMT"""

    def utcoffset(self, dt):
        return datetime.timedelta(0)

    def tzname(self, dt):
        return "GMT"

    def dst(self, dt):
        return datetime.timedelta(0)

# GMT timezone instance
gmt = GMT()
