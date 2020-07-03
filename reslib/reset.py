"""
batch mode operation.
"""

from reslib.prefs import Prefs
from reslib.cache import cache, get_root_zone, RootZone
from reslib.stats import stats
from reslib.dnssec import key_cache
from reslib.lookup import initialize_dnssec


def reset_all():
    """Reset all caches and re-init DNSSEC"""
    global RootZone
    cache.reset()
    RootZone = get_root_zone(cache)
    key_cache.reset()
    stats.reset()
    if Prefs.DNSSEC:
        initialize_dnssec()
