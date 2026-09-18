"""Pure parsing helpers behind the permission matrix.

This is where a wrong answer is dangerous but silent: the matrix is what an
admin looks at to decide who can read or write a bucket.
"""

import json

import pytest


# ─── _parse_policy_access ────────────────────────────────────────────────────

BUCKETS = ["photos", "backups", "logs"]


def _doc(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def _stmt(actions, resources, effect="Allow"):
    return {"Effect": effect, "Action": actions, "Resource": resources}


def test_readwrite_on_one_bucket(server):
    doc = _doc(_stmt(["s3:GetObject", "s3:PutObject"], ["arn:aws:s3:::photos/*"]))
    assert server._parse_policy_access(doc, BUCKETS) == {"photos": "rw"}


def test_read_only(server):
    doc = _doc(_stmt(["s3:GetObject", "s3:ListBucket"], ["arn:aws:s3:::photos/*"]))
    assert server._parse_policy_access(doc, BUCKETS) == {"photos": "r"}


def test_write_only(server):
    doc = _doc(_stmt(["s3:PutObject"], ["arn:aws:s3:::photos/*"]))
    assert server._parse_policy_access(doc, BUCKETS) == {"photos": "w"}


def test_read_and_write_from_separate_statements_merge_to_rw(server):
    doc = _doc(
        _stmt(["s3:GetObject"], ["arn:aws:s3:::photos/*"]),
        _stmt(["s3:PutObject"], ["arn:aws:s3:::photos/*"]),
    )
    assert server._parse_policy_access(doc, BUCKETS) == {"photos": "rw"}


def test_wildcard_action_grants_rw(server):
    doc = _doc(_stmt("s3:*", "arn:aws:s3:::backups/*"))
    assert server._parse_policy_access(doc, BUCKETS) == {"backups": "rw"}


@pytest.mark.parametrize("resource", ["*", "arn:aws:s3:::*", "arn:aws:s3:::*/*"])
def test_wildcard_resource_covers_every_known_bucket(server, resource):
    doc = _doc(_stmt(["s3:GetObject"], [resource]))
    assert server._parse_policy_access(doc, BUCKETS) == {b: "r" for b in BUCKETS}


def test_bucket_arn_without_object_suffix(server):
    doc = _doc(_stmt(["s3:ListBucket"], ["arn:aws:s3:::logs"]))
    assert server._parse_policy_access(doc, BUCKETS) == {"logs": "r"}


def test_deny_statements_are_ignored(server):
    """The parser only reports grants; a Deny must not be read as access."""
    doc = _doc(_stmt(["s3:GetObject", "s3:PutObject"], ["arn:aws:s3:::photos/*"],
                     effect="Deny"))
    assert server._parse_policy_access(doc, BUCKETS) == {}


def test_unknown_bucket_is_not_reported(server):
    doc = _doc(_stmt(["s3:GetObject"], ["arn:aws:s3:::deleted-bucket/*"]))
    assert server._parse_policy_access(doc, BUCKETS) == {}


def test_string_action_and_resource_are_accepted(server):
    """IAM allows both a bare string and a list in these fields."""
    doc = _doc(_stmt("s3:GetObject", "arn:aws:s3:::photos/*"))
    assert server._parse_policy_access(doc, BUCKETS) == {"photos": "r"}


def test_empty_document(server):
    assert server._parse_policy_access({}, BUCKETS) == {}
    assert server._parse_policy_access(_doc(), BUCKETS) == {}


def test_multiple_buckets_in_one_statement(server):
    doc = _doc(_stmt(["s3:GetObject", "s3:DeleteObject"],
                     ["arn:aws:s3:::photos/*", "arn:aws:s3:::logs/*"]))
    assert server._parse_policy_access(doc, BUCKETS) == {"photos": "rw", "logs": "rw"}


def test_bucket_name_is_matched_exactly_not_by_prefix(server):
    """`photos` must not pick up a grant aimed at `photos-archive`."""
    doc = _doc(_stmt(["s3:GetObject"], ["arn:aws:s3:::photos-archive/*"]))
    assert server._parse_policy_access(doc, BUCKETS + ["photos-archive"]) == {
        "photos-archive": "r"
    }


# ─── _policies_from_userinfo ─────────────────────────────────────────────────

@pytest.mark.parametrize("uinfo,expected", [
    ({"memberOf": ["readonly", "writeonly"]}, ["readonly", "writeonly"]),
    ({"memberOf": "readonly,writeonly"}, ["readonly", "writeonly"]),
    ({"policyName": "readonly,writeonly"}, ["readonly", "writeonly"]),
    ({"policyName": " readonly , writeonly "}, ["readonly", "writeonly"]),
    ({"memberOf": ["a"], "policyName": "b"}, ["a"]),   # memberOf wins
    ({"memberOf": [], "policyName": "b"}, ["b"]),      # empty falls through
    ({"policyName": ""}, []),
    ({}, []),
    (None, []),
    ("nonsense", []),
])
def test_policies_from_userinfo(server, uinfo, expected):
    assert server._policies_from_userinfo(uinfo) == expected


def test_blank_entries_are_dropped(server):
    assert server._policies_from_userinfo({"memberOf": ["a", "", None]}) == ["a"]
    assert server._policies_from_userinfo({"policyName": "a,,b"}) == ["a", "b"]


# ─── _sdk_parse ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("raw,expected", [
    ({"a": 1}, {"a": 1}),
    (json.dumps({"a": 1}), {"a": 1}),
    (json.dumps({"a": 1}).encode(), {"a": 1}),
    ("not json", {}),
    (b"not json", {}),
    (None, {}),
    ([1, 2], {}),
])
def test_sdk_parse_normalises_every_shape(server, raw, expected):
    assert server._sdk_parse(raw) == expected
