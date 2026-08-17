"""
DNS Root Trust Anchors (Root Zone KSKs).

Each entry is the presentation form of a root zone Key Signing Key
DNSKEY record. The active anchor validates the current root DNSKEY RRset;
pre-published anchors are configured ahead of a KSK rollover so that
validation continues seamlessly once the new key begins signing.

Trust anchors are the normative parameters published by IANA at
https://www.iana.org/dnssec/files (root-anchors.xml). Before adding or
changing an entry here, verify the key against IANA's published DS digest
(digest type 2 / SHA-256):

  KSK-2017  key tag 20326  DS E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
  KSK-2024  key tag 38696  DS 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16
"""

# KSK-2017: generated 2016-10-27, signing since 2018-10-11 (currently active).
KSK_2017 = (
    "257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3"
    " +/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kv"
    " ArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF"
    " 0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+e"
    " oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfd"
    " RUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwN"
    " R1AkUTV74bU="
)

# KSK-2024: generated 2024-04-26, pre-published, expected to supersede KSK-2017.
KSK_2024 = (
    "257 3 8 AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/c"
    " idltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHb"
    " GiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+s"
    " iFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqp"
    " dVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ"
    " 1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUe"
    " ayffKC73PYc="
)

# List of configured root trust anchors (DNSKEY presentation strings).
RootKeyData = [KSK_2017, KSK_2024]
