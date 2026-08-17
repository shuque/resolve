"""
Unit tests for NSEC coverage and type-bitmap helpers in reslib.dnssec.
Offline and deterministic; no network. Hand-built NSEC RRsets.

The wrap-around cases guard against regression of the bug where
nsec_covers_name() referenced the builtin `next` instead of the local
`nextname` (a TypeError on the wrap-around branch).
"""

import unittest

import dns.name
import dns.rrset
import dns.rdatatype

from reslib.dnssec import nsec_covers_name, type_in_bitmap


def make_nsec(owner, nextname, types="A RRSIG NSEC"):
    """Build an NSEC RRset with the given owner, next name, and type bitmap."""
    return dns.rrset.from_text(owner, 3600, "IN", "NSEC",
                               "{} {}".format(nextname, types))


def n(text):
    """Shorthand for dns.name.from_text."""
    return dns.name.from_text(text)


class TestNsecCoversNameNormal(unittest.TestCase):
    """Ordinary (owner < next) NSEC interval."""

    def setUp(self):
        self.nsec = make_nsec("b.example.", "d.example.")

    def test_name_inside_interval_is_covered(self):
        self.assertTrue(nsec_covers_name(self.nsec, n("c.example.")))

    def test_name_at_or_below_owner_not_covered(self):
        self.assertFalse(nsec_covers_name(self.nsec, n("a.example.")))

    def test_name_at_or_above_next_not_covered(self):
        self.assertFalse(nsec_covers_name(self.nsec, n("e.example.")))


class TestNsecCoversNameWrapAround(unittest.TestCase):
    """
    The last NSEC in a zone wraps: its next field points back to the apex,
    so owner sorts after next. This is the branch that previously crashed.
    """

    def setUp(self):
        # owner is the largest name; next is the apex (smallest).
        self.nsec = make_nsec("z.example.", "example.")

    def test_name_after_owner_is_covered(self):
        # Covered via the (name > owner) clause.
        self.assertTrue(nsec_covers_name(self.nsec, n("zz.example.")))

    def test_name_before_owner_not_covered(self):
        # name > owner is False, forcing evaluation of the second operand.
        # Pre-fix this raised TypeError ('name < next', the builtin); it
        # must now evaluate cleanly to False.
        self.assertFalse(nsec_covers_name(self.nsec, n("m.example.")))

    def test_wrap_second_clause_can_cover(self):
        # Contrived wrap (next sorts before owner but is not the apex) to
        # exercise the previously-broken (name < nextname) operand yielding
        # True.
        nsec = make_nsec("z.example.", "b.example.")
        self.assertTrue(nsec_covers_name(nsec, n("a.example.")))


class TestTypeInBitmap(unittest.TestCase):

    def setUp(self):
        self.nsec_rr = make_nsec("b.example.", "d.example.",
                                 types="A RRSIG NSEC")[0]

    def test_present_types(self):
        self.assertTrue(type_in_bitmap(dns.rdatatype.A, self.nsec_rr))
        self.assertTrue(type_in_bitmap(dns.rdatatype.NSEC, self.nsec_rr))

    def test_absent_types(self):
        self.assertFalse(type_in_bitmap(dns.rdatatype.DS, self.nsec_rr))
        self.assertFalse(type_in_bitmap(dns.rdatatype.AAAA, self.nsec_rr))


if __name__ == "__main__":
    unittest.main()
