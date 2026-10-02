"""Tests for the tool parsers, using fixtures shaped like real tool output.

The fixtures mirror output captured from Semgrep 1.177.0, Trivy 0.74.0,
OSV-Scanner 2.6.0, axe-core, Lighthouse 13.5.0 and ZAP's baseline scan.
"""

from __future__ import annotations

from pathlib import Path

from qa_agent.models.finding import Category, Severity, Tool
from qa_agent.parsers.axe import parse_axe
from qa_agent.parsers.browser import parse_page
from qa_agent.parsers.common import read_snippet, relative_location, truncate
from qa_agent.parsers.lighthouse import parse_lighthouse
from qa_agent.parsers.osv import parse_osv, severity_from_cvss
from qa_agent.parsers.semgrep import canonical_check_id, parse_semgrep
from qa_agent.parsers.trivy import parse_trivy
from qa_agent.parsers.zap import parse_zap
from qa_agent.web.page_model import NetworkFailure, PageObservation


# --------------------------------------------------------------------------
# shared helpers
# --------------------------------------------------------------------------
def test_relative_location_makes_paths_repo_relative(tmp_path):
    target = tmp_path / "src" / "main.ts"
    target.parent.mkdir(parents=True)
    target.write_text("x", encoding="utf-8")

    assert relative_location(str(target), tmp_path) == "src/main.ts"


def test_relative_location_passes_through_unrelated_paths():
    assert relative_location("some/other/file.ts", Path("/elsewhere")) == "some/other/file.ts"


def test_read_snippet_numbers_lines_and_adds_context(tmp_path):
    source = tmp_path / "a.js"
    source.write_text("\n".join(f"line{n}" for n in range(1, 11)), encoding="utf-8")

    snippet = read_snippet(source, 5, 5, context=1)

    assert "    4 | line4" in snippet
    assert "    5 | line5" in snippet
    assert "line8" not in snippet


def test_read_snippet_of_a_missing_file_is_empty(tmp_path):
    assert read_snippet(tmp_path / "nope.js", 3) == ""


def test_truncate_collapses_whitespace_and_caps_length():
    assert truncate("a   b\n c") == "a b c"
    assert len(truncate("x" * 500, 50)) == 50


# --------------------------------------------------------------------------
# semgrep
# --------------------------------------------------------------------------
SEMGREP_FIXTURE = {
    "results": [
        {
            "check_id": "C.Users.me..qa-agent.rules.semgrep.javascript.browser."
            "security.eval-detected.eval-detected",
            "path": "routes/captcha.ts",
            "start": {"line": 22, "col": 20},
            "end": {"line": 22, "col": 36},
            "extra": {
                "message": "Detected the use of eval().",
                "severity": "WARNING",
                "lines": "requires login",
                "metadata": {
                    "category": "security",
                    "cwe": ["CWE-95"],
                    "owasp": ["A03:2021 - Injection"],
                    "confidence": "LOW",
                    "source": "https://semgrep.dev/r/javascript.browser.security."
                    "eval-detected.eval-detected",
                    "references": ["https://owasp.org/Top10/A03_2021-Injection"],
                },
            },
        }
    ],
    "errors": [],
}


def test_semgrep_strips_the_local_rules_path_from_the_rule_id():
    rules_dir = Path(r"C:\Users\me\.qa-agent\rules\semgrep")
    check_id = "C.Users.me..qa-agent.rules.semgrep.javascript.browser.security.x"

    # No registry URL available, so the prefix must be derived from the path.
    assert canonical_check_id(check_id, rules_dir, {}) == "javascript.browser.security.x"


def test_semgrep_prefers_the_registry_url_for_the_rule_id():
    metadata = {"source": "https://semgrep.dev/r/python.flask.security.injection"}
    assert canonical_check_id("anything.at.all", None, metadata) == (
        "python.flask.security.injection"
    )


def test_semgrep_parses_a_result_into_a_security_finding():
    findings = parse_semgrep(SEMGREP_FIXTURE)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.tool == Tool.SEMGREP
    assert finding.category == Category.SECURITY
    assert finding.severity == Severity.MEDIUM  # WARNING -> medium
    assert finding.location == "routes/captcha.ts:22"
    assert finding.rule_id == "javascript.browser.security.eval-detected.eval-detected"
    assert finding.metadata["cwe"] == ["CWE-95"]


def test_semgrep_discards_the_requires_login_placeholder():
    # The free tier returns this literal string instead of the source line.
    assert "requires login" not in parse_semgrep(SEMGREP_FIXTURE)[0].evidence


def test_semgrep_non_security_rules_become_code_findings():
    fixture = {
        "results": [
            {
                "check_id": "best-practice.rule",
                "path": "a.js",
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {"severity": "INFO", "metadata": {"category": "best-practice"}},
            }
        ]
    }
    findings = parse_semgrep(fixture)
    assert findings[0].category == Category.CODE
    assert findings[0].severity == Severity.LOW


def test_semgrep_handles_empty_output():
    assert parse_semgrep(None) == []
    assert parse_semgrep({"results": []}) == []


# --------------------------------------------------------------------------
# trivy
# --------------------------------------------------------------------------
TRIVY_FIXTURE = {
    "Results": [
        {
            "Target": "package-lock.json",
            "Class": "lang-pkgs",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2021-23337",
                    "PkgName": "lodash",
                    "InstalledVersion": "4.17.20",
                    "FixedVersion": "4.17.21",
                    "Severity": "HIGH",
                    "Title": "Command injection in lodash",
                    "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-23337",
                }
            ],
        },
        {
            "Target": "lib/insecurity.ts",
            "Class": "secret",
            "Secrets": [
                {
                    "RuleID": "jwt-token",
                    "Category": "JWT",
                    "Severity": "MEDIUM",
                    "Title": "JWT token",
                    "StartLine": 46,
                    "Match": "eyJhbGciOi...SECRET...",
                }
            ],
        },
        {
            "Target": "Dockerfile",
            "Class": "config",
            "Misconfigurations": [
                {
                    "ID": "DS-0001",
                    "Title": "':latest' tag used",
                    "Description": "Use a specific tag.",
                    "Message": "Specify a tag in the 'FROM' statement",
                    "Severity": "MEDIUM",
                    "Resolution": "Add a tag",
                    "CauseMetadata": {"StartLine": 1},
                }
            ],
        },
    ]
}


def test_trivy_parses_all_three_result_kinds():
    findings = parse_trivy(TRIVY_FIXTURE)
    assert len(findings) == 3
    assert {f.category for f in findings} == {Category.DEPENDENCY, Category.SECURITY}


def test_trivy_vulnerability_records_package_and_fix():
    vulnerability = next(f for f in parse_trivy(TRIVY_FIXTURE) if f.rule_id == "CVE-2021-23337")

    assert vulnerability.severity == Severity.HIGH
    assert vulnerability.metadata["package"] == "lodash"
    assert vulnerability.metadata["fixed_version"] == "4.17.21"
    assert "4.17.21" in vulnerability.evidence


def test_trivy_secret_value_is_never_copied_into_the_finding():
    secret = next(f for f in parse_trivy(TRIVY_FIXTURE) if f.rule_id == "jwt-token")

    # The report gets shared; republishing the credential would be the leak.
    assert "eyJhbGciOi" not in secret.evidence
    assert "eyJhbGciOi" not in secret.description
    assert secret.location == "lib/insecurity.ts:46"


def test_trivy_misconfiguration_keeps_its_resolution():
    misconfig = next(f for f in parse_trivy(TRIVY_FIXTURE) if f.rule_id == "DS-0001")
    assert misconfig.metadata["resolution"] == "Add a tag"


def test_trivy_handles_empty_output():
    assert parse_trivy(None) == []
    assert parse_trivy({"Results": []}) == []


# --------------------------------------------------------------------------
# osv
# --------------------------------------------------------------------------
OSV_FIXTURE = {
    "results": [
        {
            "source": {"path": "package-lock.json"},
            "packages": [
                {
                    "package": {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"},
                    "vulnerabilities": [
                        {
                            "id": "GHSA-35jh-r3h4-6jhm",
                            "summary": "Command Injection in lodash",
                            "aliases": ["CVE-2021-23337"],
                            "database_specific": {"severity": "HIGH"},
                        }
                    ],
                    "groups": [
                        {"ids": ["GHSA-35jh-r3h4-6jhm"], "max_severity": "7.2"},
                    ],
                }
            ],
        }
    ]
}


def test_osv_prefers_the_cve_identifier():
    finding = parse_osv(OSV_FIXTURE)[0]
    # Trivy reports the CVE, so preferring it lets the two be merged later.
    assert finding.rule_id == "CVE-2021-23337"
    assert "CVE-2021-23337" in finding.metadata["aliases"]


def test_osv_maps_a_cvss_score_onto_the_unified_scale():
    finding = parse_osv(OSV_FIXTURE)[0]
    assert finding.severity == Severity.HIGH  # 7.2 lands in the high band
    assert finding.category == Category.DEPENDENCY


def test_severity_from_cvss_uses_the_standard_bands():
    assert severity_from_cvss(9.8) == Severity.CRITICAL
    assert severity_from_cvss(7.0) == Severity.HIGH
    assert severity_from_cvss(4.0) == Severity.MEDIUM
    assert severity_from_cvss(1.5) == Severity.LOW
    assert severity_from_cvss(None) is None
    assert severity_from_cvss("not-a-number") is None


def test_osv_falls_back_to_the_advisory_wording_without_a_score():
    fixture = {
        "results": [
            {
                "source": {"path": "requirements.txt"},
                "packages": [
                    {
                        "package": {"name": "flask", "version": "1.0", "ecosystem": "PyPI"},
                        "vulnerabilities": [
                            {"id": "GHSA-x", "database_specific": {"severity": "MODERATE"}}
                        ],
                        "groups": [{"ids": ["GHSA-x"]}],
                    }
                ],
            }
        ]
    }
    assert parse_osv(fixture)[0].severity == Severity.MEDIUM


def test_osv_handles_empty_output():
    assert parse_osv(None) == []


# --------------------------------------------------------------------------
# axe
# --------------------------------------------------------------------------
AXE_FIXTURE = {
    "violations": [
        {
            "id": "color-contrast",
            "impact": "serious",
            "help": "Elements must have sufficient colour contrast",
            "description": "Ensures contrast between foreground and background",
            "helpUrl": "https://dequeuniversity.com/rules/axe/4.8/color-contrast",
            "tags": ["wcag2aa", "wcag143", "cat.color"],
            "nodes": [
                {"target": [".btn"], "html": "<button class='btn'>Buy</button>"},
                {"target": [".link"], "html": "<a class='link'>More</a>"},
            ],
        }
    ]
}


def test_axe_maps_impact_one_step_below_the_security_scale():
    finding = parse_axe(AXE_FIXTURE, "http://localhost:3000/")[0]

    assert finding.severity == Severity.MEDIUM  # serious -> medium
    assert finding.metadata["axe_impact"] == "serious"
    assert finding.category == Category.ACCESSIBILITY


def test_axe_keeps_wcag_tags_and_node_count():
    finding = parse_axe(AXE_FIXTURE, "http://localhost:3000/")[0]

    assert "wcag2aa" in finding.metadata["wcag"]
    assert "cat.color" not in finding.metadata["wcag"]
    assert finding.metadata["node_count"] == 2
    assert "2 element(s)" in finding.evidence


def test_axe_references_the_screenshot_when_given():
    finding = parse_axe(AXE_FIXTURE, "http://x/", screenshot="00-home.png")[0]
    assert "00-home.png" in finding.evidence


def test_axe_handles_empty_output():
    assert parse_axe(None, "http://x/") == []
    assert parse_axe({"violations": []}, "http://x/") == []


# --------------------------------------------------------------------------
# lighthouse
# --------------------------------------------------------------------------
LIGHTHOUSE_FIXTURE = {
    "categories": {
        "performance": {
            "title": "Performance",
            "score": 0.34,
            "auditRefs": [{"id": "uses-long-cache-ttl", "weight": 4}],
        },
        "seo": {"title": "SEO", "score": 0.95, "auditRefs": []},
    },
    "audits": {
        "uses-long-cache-ttl": {
            "title": "Serve static assets with an efficient cache policy",
            "score": 0.1,
            "displayValue": "12 resources found",
        },
        "largest-contentful-paint": {"displayValue": "4.2 s"},
    },
}

BUDGETS = {"performance": 50, "best-practices": 70, "seo": 70}


def test_lighthouse_reports_a_category_below_budget():
    findings = parse_lighthouse(LIGHTHOUSE_FIXTURE, "http://localhost:3000/", budgets=BUDGETS)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.category == Category.PERFORMANCE
    assert finding.metadata["score"] == 34
    # 34 is 16 points under the budget of 50, but not below half of it (25),
    # so it is a medium rather than a high.
    assert finding.severity == Severity.MEDIUM


def test_lighthouse_severity_escalates_when_the_score_collapses():
    fixture = {
        "categories": {"performance": {"title": "Performance", "score": 0.1, "auditRefs": []}},
        "audits": {},
    }
    finding = parse_lighthouse(fixture, "http://x/", budgets=BUDGETS)[0]
    assert finding.severity == Severity.HIGH


def test_lighthouse_ignores_categories_that_meet_budget():
    findings = parse_lighthouse(LIGHTHOUSE_FIXTURE, "http://x/", budgets=BUDGETS)
    assert all(f.metadata["lighthouse_category"] != "seo" for f in findings)


def test_lighthouse_explains_why_the_score_is_low():
    finding = parse_lighthouse(LIGHTHOUSE_FIXTURE, "http://x/", budgets=BUDGETS)[0]

    assert "efficient cache policy" in finding.evidence
    assert "largest-contentful-paint=4.2 s" in finding.evidence


def test_a_poor_largest_contentful_paint_is_reported_even_with_a_good_score():
    # Observed on the evaluation app: score 71/100 (above budget) with a 4.7 s LCP.
    fixture = {
        "categories": {"performance": {"title": "Performance", "score": 0.71, "auditRefs": []}},
        "audits": {
            "largest-contentful-paint": {"numericValue": 4712, "displayValue": "4.7 s"},
            "cumulative-layout-shift": {"numericValue": 0.01},
        },
    }
    findings = parse_lighthouse(fixture, "http://x/", budgets=BUDGETS)

    assert [f.rule_id for f in findings] == ["lighthouse:performance:lcp"]
    assert findings[0].metadata["lcp_ms"] == 4712


def test_a_poor_layout_shift_is_reported():
    fixture = {
        "categories": {},
        "audits": {"cumulative-layout-shift": {"numericValue": 0.4}},
    }
    findings = parse_lighthouse(fixture, "http://x/", budgets=BUDGETS)
    assert [f.rule_id for f in findings] == ["lighthouse:performance:cls"]


def test_lighthouse_handles_empty_output():
    assert parse_lighthouse(None, "http://x/", budgets=BUDGETS) == []


# --------------------------------------------------------------------------
# zap
# --------------------------------------------------------------------------
ZAP_FIXTURE = {
    "site": [
        {
            "@name": "http://host.docker.internal:3000",
            "alerts": [
                {
                    "pluginid": "10038",
                    "alert": "Content Security Policy (CSP) Header Not Set",
                    "riskcode": "2",
                    "confidence": "3",
                    "desc": "<p>CSP is an added layer of security.</p>",
                    "solution": "<p>Configure the header.</p>",
                    "reference": "https://owasp.org/csp\nhttps://example.com/more",
                    "cweid": "693",
                    "count": "2",
                    "instances": [
                        {"uri": "http://host.docker.internal:3000/", "method": "GET"},
                        {"uri": "http://host.docker.internal:3000/ftp", "method": "GET"},
                    ],
                }
            ],
        }
    ]
}


def test_zap_maps_risk_codes_to_severities():
    finding = parse_zap(ZAP_FIXTURE)[0]
    assert finding.severity == Severity.MEDIUM  # riskcode 2
    assert finding.category == Category.SECURITY
    assert finding.rule_id == "zap:10038"


def test_zap_strips_html_from_its_prose():
    finding = parse_zap(ZAP_FIXTURE)[0]
    assert "<p>" not in finding.description
    assert "added layer of security" in finding.description


def test_zap_collects_instances_and_references():
    finding = parse_zap(ZAP_FIXTURE)[0]
    assert "/ftp" in finding.evidence
    assert "https://owasp.org/csp" in finding.references


def test_zap_handles_empty_output():
    assert parse_zap(None) == []
    assert parse_zap({"site": []}) == []


# --------------------------------------------------------------------------
# browser observations
# --------------------------------------------------------------------------
def test_uncaught_exception_outranks_a_console_error():
    page = PageObservation(
        url="http://localhost:3000/",
        console_errors=["Uncaught exception: TypeError: x is not a function", "plain error"],
    )
    findings = parse_page(page)

    uncaught = next(f for f in findings if "Uncaught" in f.title)
    plain = next(f for f in findings if "console error" in f.title)
    assert uncaught.severity == Severity.HIGH
    assert plain.severity == Severity.MEDIUM
    assert uncaught.category == Category.FUNCTIONAL


def test_server_errors_outrank_client_errors():
    page = PageObservation(
        url="http://localhost:3000/",
        network_failures=[
            NetworkFailure(url="http://x/api", status=500, resource_type="fetch"),
            NetworkFailure(url="http://x/missing.png", status=404, resource_type="image"),
        ],
    )
    findings = parse_page(page)

    assert any(f.severity == Severity.HIGH for f in findings)
    # A missing image is cosmetic, not a broken feature.
    assert any(f.severity == Severity.LOW for f in findings)


def test_a_page_that_will_not_load_is_a_high_severity_finding():
    page = PageObservation(url="http://localhost:3000/x", load_error="Timeout 30000ms exceeded")
    findings = parse_page(page)

    assert findings[0].title == "Page failed to load"
    assert findings[0].severity == Severity.HIGH


def test_an_error_status_on_the_page_itself_is_reported():
    page = PageObservation(url="http://localhost:3000/x", status=500)
    assert any("HTTP 500" in f.title for f in parse_page(page))


def test_a_healthy_page_produces_no_findings():
    assert parse_page(PageObservation(url="http://localhost:3000/", status=200)) == []
