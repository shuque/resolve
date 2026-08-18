"""
Resolver: encapsulates all operational state for one resolution engine.

Owns prefs, cache, key_cache, stats, and the root zone. Construction does
no I/O; call bootstrap() before resolving. Multiple independent Resolver
instances may coexist in one process.
"""

from reslib.prefs import Prefs


class Resolver:
    """Holds all mutable, resolver-scoped state."""

    def __init__(self, prefs=None):
        self.prefs = prefs if prefs is not None else Prefs()
        # Cache/KeyCache/Stats imported lazily to avoid an import cycle
        # during construction; self.prefs is set first.
        from reslib.cache import Cache
        from reslib.dnssec import KeyCache
        from reslib.stats import Stats
        self.cache = Cache(resolver=self)
        self.key_cache = KeyCache(resolver=self)
        self.stats = Stats()
        self.root_zone = None
        self._dnssec_initialized = False

    def bootstrap(self):
        """Build the root zone from hints and, if DNSSEC is enabled,
        install the root trust anchors. Idempotent."""
        from reslib.cache import get_root_zone
        if self.root_zone is None:
            self.root_zone = get_root_zone(self.cache)
        if self.prefs.DNSSEC and not self._dnssec_initialized:
            self._init_dnssec()
            self._dnssec_initialized = True
        return self.root_zone

    def _init_dnssec(self):
        """Fetch + authenticate the root DNSKEY set and install it,
        delegating to the resolver-aware lookup.initialize_dnssec()."""
        from reslib.lookup import initialize_dnssec
        initialize_dnssec(self)

    def reset(self):
        """Re-initialize all state and rebuild the root zone."""
        from reslib.cache import Cache
        from reslib.dnssec import KeyCache
        from reslib.stats import Stats
        self.cache = Cache(resolver=self)
        self.key_cache = KeyCache(resolver=self)
        self.stats = Stats()
        self.root_zone = None
        self._dnssec_initialized = False
        self.bootstrap()
