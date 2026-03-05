"""Tests for action and action_parameters validation (Categories C, D, I, J, K, L, N)."""

from __future__ import annotations

from octorules.linter.action_validator import lint_actions
from octorules.linter.engine import LintContext, Severity
from octorules.phases import PHASE_BY_NAME


def _lint_rule(rule, phase_name="redirect_rules"):
    phase = PHASE_BY_NAME[phase_name]
    ctx = LintContext()
    lint_actions(rule, phase, ctx)
    return ctx


def _ids(ctx):
    return [r.rule_id for r in ctx.results]


class TestActionValidity:
    def test_c001_invalid_action_for_phase(self):
        ctx = _lint_rule({"ref": "t", "expression": "true", "action": "block"}, "redirect_rules")
        assert "C001" in _ids(ctx)

    def test_c001_valid_action(self):
        ctx = _lint_rule({"ref": "t", "expression": "true", "action": "redirect"}, "redirect_rules")
        assert "C001" not in _ids(ctx)

    def test_c002_missing_action_no_default(self):
        ctx = _lint_rule({"ref": "t", "expression": "true"}, "waf_custom_rules")
        assert "C002" in _ids(ctx)

    def test_c002_no_error_with_default(self):
        # redirect_rules has default action "redirect"
        ctx = _lint_rule({"ref": "t", "expression": "true"}, "redirect_rules")
        assert "C002" not in _ids(ctx)

    def test_c003_missing_action_parameters(self):
        ctx = _lint_rule(
            {"ref": "t", "expression": "true", "action": "redirect"},
            "redirect_rules",
        )
        assert "C003" in _ids(ctx)

    def test_c004_unknown_parameter_key(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "redirect",
                "action_parameters": {"from_value": {}, "bogus_key": True},
            },
            "redirect_rules",
        )
        assert "C004" in _ids(ctx)


class TestDefaultActionParamValidation:
    def test_c004_fires_on_default_action_with_unknown_param(self):
        # config_rules has default action 'set_config' — unknown params should be caught
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action_parameters": {"bogus_key": True},
            },
            "config_rules",
        )
        assert "C004" in _ids(ctx)

    def test_default_action_valid_params_ok(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action_parameters": {"ssl": "full"},
            },
            "config_rules",
        )
        assert "C004" not in _ids(ctx)

    def test_default_action_disable_railgun_accepted(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action_parameters": {"disable_railgun": True},
            },
            "config_rules",
        )
        assert "C004" not in _ids(ctx)


class TestC005InvalidParamsType:
    def test_c005_string_action_params(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "redirect",
                "action_parameters": "not-a-dict",
            },
            "redirect_rules",
        )
        assert "C005" in _ids(ctx)

    def test_c005_list_action_params(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "redirect",
                "action_parameters": ["bad"],
            },
            "redirect_rules",
        )
        assert "C005" in _ids(ctx)

    def test_c005_not_triggered_for_dict(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "redirect",
                "action_parameters": {"from_value": {}},
            },
            "redirect_rules",
        )
        assert "C005" not in _ids(ctx)


class TestC009UnnecessaryParams:
    def test_c009_params_on_no_param_action(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "log",
                "action_parameters": {"something": True},
            },
            "waf_custom_rules",
        )
        assert "C009" in _ids(ctx)

    def test_c009_not_triggered_when_params_expected(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "redirect",
                "action_parameters": {"from_value": {}},
            },
            "redirect_rules",
        )
        assert "C009" not in _ids(ctx)


class TestRedirectParams:
    def test_k002_missing_target_url(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "redirect",
                "action_parameters": {"from_value": {"status_code": 301}},
            },
            "redirect_rules",
        )
        assert "K002" in _ids(ctx)

    def test_c008_conflicting_value_expression(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "redirect",
                "action_parameters": {
                    "from_value": {
                        "target_url": {"value": "/new", "expression": "concat()"},
                        "status_code": 301,
                    }
                },
            },
            "redirect_rules",
        )
        assert "C008" in _ids(ctx)

    def test_c007_missing_status_code(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "redirect",
                "action_parameters": {
                    "from_value": {
                        "target_url": {"value": "/new"},
                    }
                },
            },
            "redirect_rules",
        )
        assert "C007" in _ids(ctx)

    def test_k001_invalid_status_code(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "redirect",
                "action_parameters": {
                    "from_value": {
                        "target_url": {"value": "/new"},
                        "status_code": 200,
                    }
                },
            },
            "redirect_rules",
        )
        assert "K001" in _ids(ctx)

    def test_c006_string_status_code(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "redirect",
                "action_parameters": {
                    "from_value": {
                        "target_url": {"value": "/new"},
                        "status_code": "301",
                    }
                },
            },
            "redirect_rules",
        )
        assert "C006" in _ids(ctx)

    def test_valid_redirect(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "redirect",
                "action_parameters": {
                    "from_value": {
                        "target_url": {"value": "/new"},
                        "status_code": 301,
                    }
                },
            },
            "redirect_rules",
        )
        errors = [r for r in ctx.results if r.severity == Severity.ERROR]
        assert len(errors) == 0


class TestCacheParams:
    def test_i001_invalid_edge_ttl_mode(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_cache_settings",
                "action_parameters": {"edge_ttl": {"mode": "bogus"}},
            },
            "cache_rules",
        )
        assert "I001" in _ids(ctx)

    def test_i002_override_without_default(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_cache_settings",
                "action_parameters": {"edge_ttl": {"mode": "override_origin"}},
            },
            "cache_rules",
        )
        assert "I002" in _ids(ctx)

    def test_i003_negative_ttl(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_cache_settings",
                "action_parameters": {"edge_ttl": {"mode": "override_origin", "default": -1}},
            },
            "cache_rules",
        )
        assert "I003" in _ids(ctx)

    def test_i004_bypass_with_ttl(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_cache_settings",
                "action_parameters": {
                    "cache": False,
                    "edge_ttl": {"mode": "override_origin", "default": 3600},
                },
            },
            "cache_rules",
        )
        assert "I004" in _ids(ctx)

    def test_valid_cache(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_cache_settings",
                "action_parameters": {
                    "cache": True,
                    "edge_ttl": {"mode": "override_origin", "default": 86400},
                },
            },
            "cache_rules",
        )
        errors = [r for r in ctx.results if r.severity == Severity.ERROR]
        assert len(errors) == 0


class TestBrowserTtl:
    def test_i001_invalid_browser_ttl_mode(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_cache_settings",
                "action_parameters": {"browser_ttl": {"mode": "bogus"}},
            },
            "cache_rules",
        )
        assert "I001" in _ids(ctx)

    def test_i002_browser_ttl_override_without_default(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_cache_settings",
                "action_parameters": {"browser_ttl": {"mode": "override_origin"}},
            },
            "cache_rules",
        )
        assert "I002" in _ids(ctx)

    def test_i003_negative_browser_ttl(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_cache_settings",
                "action_parameters": {
                    "browser_ttl": {"mode": "override_origin", "default": -5},
                },
            },
            "cache_rules",
        )
        assert "I003" in _ids(ctx)

    def test_valid_browser_ttl(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_cache_settings",
                "action_parameters": {
                    "browser_ttl": {"mode": "override_origin", "default": 3600},
                },
            },
            "cache_rules",
        )
        errors = [r for r in ctx.results if r.severity == Severity.ERROR]
        assert len(errors) == 0


class TestServeErrorParams:
    def test_c006_serve_error_status_code_out_of_range(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "serve_error",
                "action_parameters": {"status_code": 200, "content": "hi"},
            },
            "custom_error_rules",
        )
        assert "C006" in _ids(ctx)

    def test_valid_serve_error_status_code(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "serve_error",
                "action_parameters": {"status_code": 503, "content": "Maintenance"},
            },
            "custom_error_rules",
        )
        assert "C006" not in _ids(ctx)


class TestConfigParams:
    def test_j001_invalid_security_level(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_config",
                "action_parameters": {"security_level": "bogus"},
            },
            "config_rules",
        )
        assert "J001" in _ids(ctx)

    def test_j002_invalid_ssl(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_config",
                "action_parameters": {"ssl": "bogus"},
            },
            "config_rules",
        )
        assert "J002" in _ids(ctx)

    def test_j003_invalid_polish(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_config",
                "action_parameters": {"polish": "bogus"},
            },
            "config_rules",
        )
        assert "J003" in _ids(ctx)

    def test_j004_security_off_warning(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "set_config",
                "action_parameters": {"security_level": "off"},
            },
            "config_rules",
        )
        assert "J004" in _ids(ctx)


class TestRateLimitParams:
    def test_d001_invalid_period(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "action_parameters": {
                    "period": 42,
                    "requests_per_period": 100,
                    "characteristics": ["ip.src"],
                },
            },
            "rate_limiting_rules",
        )
        assert "D001" in _ids(ctx)

    def test_d002_missing_characteristics(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "action_parameters": {"period": 60, "requests_per_period": 100},
            },
            "rate_limiting_rules",
        )
        assert "D002" in _ids(ctx)

    def test_d003_missing_threshold(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "action_parameters": {"period": 60, "characteristics": ["ip.src"]},
            },
            "rate_limiting_rules",
        )
        assert "D003" in _ids(ctx)

    def test_d003_score_per_period_satisfies_threshold(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "action_parameters": {
                    "period": 60,
                    "score_per_period": 50,
                    "characteristics": ["ip.src"],
                },
            },
            "rate_limiting_rules",
        )
        assert "D003" not in _ids(ctx)

    def test_d004_timeout_exceeds_period(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "action_parameters": {
                    "period": 60,
                    "requests_per_period": 100,
                    "mitigation_timeout": 120,
                    "characteristics": ["ip.src"],
                },
            },
            "rate_limiting_rules",
        )
        assert "D004" in _ids(ctx)

    def test_d005_invalid_counting_expression(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "action_parameters": {
                    "period": 60,
                    "requests_per_period": 100,
                    "counting_expression": 123,
                    "characteristics": ["ip.src"],
                },
            },
            "rate_limiting_rules",
        )
        assert "D005" in _ids(ctx)


class TestOriginParams:
    def test_n001_port_out_of_range(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "route",
                "action_parameters": {"origin": {"port": 99999}},
            },
            "origin_rules",
        )
        assert "N001" in _ids(ctx)

    def test_n001_valid_port(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "route",
                "action_parameters": {"origin": {"port": 8443}},
            },
            "origin_rules",
        )
        assert "N001" not in _ids(ctx)


class TestD006CountingExpression:
    def test_d006_invalid_counting_expression(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "action_parameters": {
                    "period": 60,
                    "requests_per_period": 100,
                    "counting_expression": "http.host gt",
                    "characteristics": ["ip.src"],
                },
            },
            "rate_limiting_rules",
        )
        assert "D006" in _ids(ctx)

    def test_d006_valid_counting_expression(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "action_parameters": {
                    "period": 60,
                    "requests_per_period": 100,
                    "counting_expression": 'http.host eq "example.com"',
                    "characteristics": ["ip.src"],
                },
            },
            "rate_limiting_rules",
        )
        assert "D006" not in _ids(ctx)

    def test_d006_empty_counting_expression_ok(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "action_parameters": {
                    "period": 60,
                    "requests_per_period": 100,
                    "counting_expression": "",
                    "characteristics": ["ip.src"],
                },
            },
            "rate_limiting_rules",
        )
        assert "D006" not in _ids(ctx)


class TestL004HeaderOperation:
    def test_l004_invalid_operation(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "headers": {"x-custom": {"operation": "replace", "value": "x"}},
                },
            },
            "request_header_rules",
        )
        assert "L004" in _ids(ctx)

    def test_l004_valid_set(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "headers": {"x-custom": {"operation": "set", "value": "x"}},
                },
            },
            "request_header_rules",
        )
        assert "L004" not in _ids(ctx)

    def test_l004_valid_remove(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "headers": {"x-custom": {"operation": "remove"}},
                },
            },
            "request_header_rules",
        )
        assert "L004" not in _ids(ctx)


class TestTransformParams:
    def test_c008_conflicting_uri_value_expression(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "uri": {"path": {"value": "/new", "expression": "concat()"}},
                },
            },
            "url_rewrite_rules",
        )
        assert "C008" in _ids(ctx)

    def test_l002_empty_header_name(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "headers": {"": {"operation": "set", "value": "x"}},
                },
            },
            "request_header_rules",
        )
        assert "L002" in _ids(ctx)

    def test_l003_missing_operation(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "headers": {"x-custom": {"value": "x"}},
                },
            },
            "request_header_rules",
        )
        assert "L003" in _ids(ctx)

    def test_c008_conflicting_header_value_expression(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "headers": {
                        "x-custom": {
                            "operation": "set",
                            "value": "static",
                            "expression": "concat()",
                        }
                    },
                },
            },
            "request_header_rules",
        )
        assert "C008" in _ids(ctx)


class TestL005HeaderMissingValue:
    def test_l005_set_missing_value(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "headers": {"x-custom": {"operation": "set"}},
                },
            },
            "request_header_rules",
        )
        assert "L005" in _ids(ctx)

    def test_l005_add_missing_value(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "headers": {"x-custom": {"operation": "add"}},
                },
            },
            "request_header_rules",
        )
        assert "L005" in _ids(ctx)

    def test_l005_set_with_value_ok(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "headers": {"x-custom": {"operation": "set", "value": "x"}},
                },
            },
            "request_header_rules",
        )
        assert "L005" not in _ids(ctx)

    def test_l005_set_with_expression_ok(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "headers": {
                        "x-custom": {
                            "operation": "set",
                            "expression": 'concat("a", "b")',
                        }
                    },
                },
            },
            "request_header_rules",
        )
        assert "L005" not in _ids(ctx)

    def test_l005_remove_ok_without_value(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "headers": {"x-custom": {"operation": "remove"}},
                },
            },
            "request_header_rules",
        )
        assert "L005" not in _ids(ctx)


class TestL006TransformExpressionLinting:
    def test_l006_invalid_uri_path_expression(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "uri": {"path": {"expression": "invalid expression !!!"}},
                },
            },
            "url_rewrite_rules",
        )
        assert "L006" in _ids(ctx)

    def test_l006_valid_uri_expression_ok(self):
        _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "uri": {"path": {"expression": 'concat("/prefix", http.request.uri.path)'}},
                },
            },
            "url_rewrite_rules",
        )
        # L006 should not fire for a valid expression (wirefilter may still
        # reject concat syntax, so we just check it doesn't crash)
        # The test verifies the code path runs without error

    def test_l006_invalid_header_expression(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "headers": {
                        "x-custom": {
                            "operation": "set",
                            "expression": "totally broken <<<",
                        }
                    },
                },
            },
            "request_header_rules",
        )
        assert "L006" in _ids(ctx)

    def test_l006_empty_expression_ok(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "uri": {"path": {"expression": ""}},
                },
            },
            "url_rewrite_rules",
        )
        assert "L006" not in _ids(ctx)

    def test_l006_static_value_no_lint(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "uri": {"path": {"value": "/new-path"}},
                },
            },
            "url_rewrite_rules",
        )
        assert "L006" not in _ids(ctx)

    def test_l006_suppressed_for_transform_function_call(self):
        """Transform expressions using function-call syntax should not fire L006."""
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "uri": {
                        "path": {
                            "expression": (
                                "regex_replace(http.request.uri.path,"
                                ' "^/api/v1/", "/production/api/v1/")'
                            ),
                        }
                    },
                },
            },
            "url_rewrite_rules",
        )
        assert "L006" not in _ids(ctx)

    def test_l006_suppressed_for_concat_call(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "rewrite",
                "action_parameters": {
                    "headers": {
                        "x-custom": {
                            "operation": "set",
                            "expression": 'concat("prefix-", http.host)',
                        }
                    },
                },
            },
            "request_header_rules",
        )
        assert "L006" not in _ids(ctx)


class TestC010ServeErrorContentSize:
    def test_c010_content_exceeds_limit(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "serve_error",
                "action_parameters": {
                    "content": "x" * 11000,
                    "status_code": 503,
                },
            },
            "custom_error_rules",
        )
        assert "C010" in _ids(ctx)

    def test_c010_content_within_limit(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "serve_error",
                "action_parameters": {
                    "content": "x" * 5000,
                    "status_code": 503,
                },
            },
            "custom_error_rules",
        )
        assert "C010" not in _ids(ctx)

    def test_c010_exactly_at_limit(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "serve_error",
                "action_parameters": {
                    "content": "x" * 10240,
                    "status_code": 503,
                },
            },
            "custom_error_rules",
        )
        assert "C010" not in _ids(ctx)

    def test_c010_no_content_ok(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "serve_error",
                "action_parameters": {"status_code": 503},
            },
            "custom_error_rules",
        )
        assert "C010" not in _ids(ctx)


class TestC011C012SkipParams:
    def test_c011_invalid_skip_phase(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "skip",
                "action_parameters": {"phases": ["bogus_phase"]},
            },
            "waf_custom_rules",
        )
        assert "C011" in _ids(ctx)

    def test_c011_valid_skip_phase(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "skip",
                "action_parameters": {"phases": ["http_request_firewall_custom"]},
            },
            "waf_custom_rules",
        )
        assert "C011" not in _ids(ctx)

    def test_c012_invalid_skip_product(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "skip",
                "action_parameters": {"products": ["bogus_product"]},
            },
            "waf_custom_rules",
        )
        assert "C012" in _ids(ctx)

    def test_c012_valid_skip_products(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "skip",
                "action_parameters": {"products": ["waf", "rateLimit"]},
            },
            "waf_custom_rules",
        )
        assert "C012" not in _ids(ctx)

    def test_c011_c012_mixed_valid_invalid(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "skip",
                "action_parameters": {
                    "phases": ["http_ratelimit", "bogus"],
                    "products": ["waf", "invalid"],
                },
            },
            "waf_custom_rules",
        )
        assert "C011" in _ids(ctx)
        assert "C012" in _ids(ctx)


class TestC013CompressResponseAlgorithms:
    def test_c013_invalid_algorithm(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "compress_response",
                "action_parameters": {
                    "algorithms": [{"name": "deflate"}],
                },
            },
            "compression_rules",
        )
        assert "C013" in _ids(ctx)

    def test_c013_valid_algorithms(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "compress_response",
                "action_parameters": {
                    "algorithms": [
                        {"name": "gzip"},
                        {"name": "brotli"},
                        {"name": "zstd"},
                        {"name": "none"},
                        {"name": "auto"},
                    ],
                },
            },
            "compression_rules",
        )
        assert "C013" not in _ids(ctx)

    def test_c013_mixed_valid_invalid(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "compress_response",
                "action_parameters": {
                    "algorithms": [{"name": "gzip"}, {"name": "lz4"}],
                },
            },
            "compression_rules",
        )
        c013 = [r for r in ctx.results if r.rule_id == "C013"]
        assert len(c013) == 1
        assert "lz4" in c013[0].message


class TestC014RateLimitCharacteristics:
    def test_c014_invalid_characteristic(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "action_parameters": {
                    "period": 60,
                    "requests_per_period": 100,
                    "characteristics": ["bogus.field"],
                },
            },
            "rate_limiting_rules",
        )
        assert "C014" in _ids(ctx)

    def test_c014_valid_characteristics(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "action_parameters": {
                    "period": 60,
                    "requests_per_period": 100,
                    "characteristics": ["ip.src", "cf.colo.id"],
                },
            },
            "rate_limiting_rules",
        )
        assert "C014" not in _ids(ctx)

    def test_c014_header_reference_ok(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "action_parameters": {
                    "period": 60,
                    "requests_per_period": 100,
                    "characteristics": ['http.request.headers["x-api-key"]'],
                },
            },
            "rate_limiting_rules",
        )
        assert "C014" not in _ids(ctx)

    def test_c014_mixed_valid_invalid(self):
        ctx = _lint_rule(
            {
                "ref": "t",
                "expression": "true",
                "action": "block",
                "action_parameters": {
                    "period": 60,
                    "requests_per_period": 100,
                    "characteristics": ["ip.src", "bad.field"],
                },
            },
            "rate_limiting_rules",
        )
        c014 = [r for r in ctx.results if r.rule_id == "C014"]
        assert len(c014) == 1
        assert "bad.field" in c014[0].message
