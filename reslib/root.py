"""
Root server names and addresses.
"""

ROOTHINTS = [
    ("a.root-servers.net.", "198.41.0.4"),
    ("a.root-servers.net.", "2001:503:ba3e::2:30"),
    ("b.root-servers.net.", "199.9.14.201"),
    ("b.root-servers.net.", "2001:500:200::b"),
    ("c.root-servers.net.", "192.33.4.12"),
    ("c.root-servers.net.", "2001:500:2::c"),
    ("d.root-servers.net.", "199.7.91.13"),
    ("d.root-servers.net.", "2001:500:2d::d"),
    ("e.root-servers.net.", "192.203.230.10"),
    ("e.root-servers.net.", "2001:500:a8::e"),
    ("f.root-servers.net.", "192.5.5.241"),
    ("f.root-servers.net.", "2001:500:2f::f"),
    ("g.root-servers.net.", "192.112.36.4"),
    ("g.root-servers.net.", "2001:500:12::d0d"),
    ("h.root-servers.net.", "198.97.190.53"),
    ("h.root-servers.net.", "2001:500:1::53"),
    ("i.root-servers.net.", "192.36.148.17"),
    ("i.root-servers.net.", "2001:7fe::53"),
    ("j.root-servers.net.", "192.58.128.30"),
    ("j.root-servers.net.", "2001:503:c27::2:30"),
    ("k.root-servers.net.", "193.0.14.129"),
    ("k.root-servers.net.", "2001:7fd::1"),
    ("l.root-servers.net.", "199.7.83.42"),
    ("l.root-servers.net.", "2001:500:9f::42"),
    ("m.root-servers.net.", "202.12.27.33"),
    ("m.root-servers.net.", "2001:dc3::35"),
]

"""
DNS Root Trust Anchor.

This is the Root Zone KSK that was generated and published in 2017 and
rolled into use on October 11th 2018. Commonly referred to as KSK-2017.
"""

RootKeyData = "257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3 +/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kv ArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF 0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+e oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfd RUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwN R1AkUTV74bU="


