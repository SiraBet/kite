"""Version ordering as dpkg and rpm define it, and CVSS v3 base scores."""
import pytest

from app.versioncmp import cvss3_base_score, dpkg_compare, rpm_compare, severity_from_score


@pytest.mark.parametrize("a,b,expected", [
    ("1.0", "1.0", 0),
    ("1.0", "1.1", -1),
    ("1.0~rc1", "1.0", -1),                       # ~ sorts before the end
    ("1.0~rc1", "1.0~rc2", -1),
    ("1:0.9", "2.0", 1),                          # epoch wins
    ("3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.5", -1),
    ("3.0.13-0ubuntu3.10", "3.0.13-0ubuntu3.9", 1),  # numeric, not lexical
    ("2.39-0ubuntu8.3", "2.39-0ubuntu8", 1),
    ("1.0a", "1.0", 1),
    ("1.0+dfsg-1", "1.0-1", 1),
    ("7.0.0-1011.11~24.04.1", "7.0.0-1011.11", -1),
    ("1.2.3", "1.2.3-0", 0),                      # no revision = 0
])
def test_dpkg_order(a, b, expected):
    assert dpkg_compare(a, b) == expected
    assert dpkg_compare(b, a) == -expected


@pytest.mark.parametrize("a,b,expected", [
    ("1:3.0.7-27.el9", "1:3.0.7-27.el9", 0),
    ("1:3.0.7-25.el9", "1:3.0.7-27.el9", -1),
    ("3.0.7-27.el9", "1:3.0.7-25.el9", -1),       # missing epoch = 0
    ("1:1.1.1g-15.el8_3", "1:1.1.1k-7.el8_6", -1),
    ("5.1.8-9.el9", "5.1.8-10.el9", -1),
    ("2.0~beta1-1", "2.0-1", -1),
    ("2.0^git1-1", "2.0-1", 1),
    ("1.10-1", "1.9-1", 1),
    ("1.0-1.el9_2", "1.0-1.el9", 1),
])
def test_rpm_order(a, b, expected):
    assert rpm_compare(a, b) == expected
    assert rpm_compare(b, a) == -expected


def test_cvss_scores_and_severity():
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N") == 7.4
    assert cvss3_base_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N") == 5.5
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
    assert cvss3_base_score("garbage") is None
    assert [severity_from_score(s) for s in (9.8, 7.4, 5.5, 2.0, None)] == ["critical", "important", "moderate", "low", "unknown"]
