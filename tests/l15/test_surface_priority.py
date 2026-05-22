"""Tests for iter-25.7 — surface priority labels."""

from __future__ import annotations

from strix.l15.surface_priority import (
    classify_surface,
    depth_multiplier_for,
)


# --------------------------------------------------------------------
# Critical paths
# --------------------------------------------------------------------

def test_admin_is_critical():
    c = classify_surface("https://app.example.com/admin")
    assert c.label == "critical"
    assert c.depth_multiplier == 3.0


def test_admin_subpath_is_critical():
    c = classify_surface("https://app.example.com/admin/users/42")
    assert c.label == "critical"


def test_api_versioned_admin_is_critical():
    """iter-27 fix: `/api/v1/admin/*` paths must classify as
    critical. The original regex only matched the top-level
    `/admin/*` pattern, so `/api/v1/admin/users` returned `normal`
    — surfaced by the F.4 maximal-finding test which had to use
    `/admin/users/42` instead of `/api/v1/admin/users/42`.
    """
    for path in (
        "https://app.example.com/api/v1/admin/users",
        "https://app.example.com/api/v2/admin/dashboard",
        "https://app.example.com/api/v3/admin/",
        "https://app.example.com/api/admin/users",  # no version
    ):
        c = classify_surface(path)
        assert c.label == "critical", (
            f"{path} should classify as critical; got {c.label}"
        )


def test_payment_api_is_critical():
    c = classify_surface("https://api.example.com/api/v1/payment/charge")
    assert c.label == "critical"


def test_auth_endpoints_critical():
    for path in (
        "/api/v1/auth/login",
        "/api/v2/login",
        "/api/v1/oauth/token",
        "/api/v1/password/reset",
        "/api/v1/sso",
    ):
        c = classify_surface(f"https://e.com{path}")
        assert c.label == "critical", f"{path} should be critical"


def test_wp_admin_critical():
    c = classify_surface("https://wp.example.com/wp-admin")
    assert c.label == "critical"


def test_spring_actuator_critical():
    c = classify_surface("https://api.example.com/actuator/health")
    assert c.label == "critical"


# --------------------------------------------------------------------
# High paths
# --------------------------------------------------------------------

def test_user_api_is_high():
    c = classify_surface("https://api.example.com/api/v1/users/me")
    assert c.label == "high"


def test_oauth_callback_high():
    c = classify_surface("https://e.com/oauth/callback")
    assert c.label == "high"


def test_password_reset_high():
    c = classify_surface("https://e.com/reset-password")
    assert c.label == "high"


def test_file_upload_high():
    c = classify_surface("https://e.com/api/v1/upload")
    assert c.label == "high"


# --------------------------------------------------------------------
# Low paths
# --------------------------------------------------------------------

def test_static_assets_low():
    for path in (
        "/static/img.png",
        "/assets/main.css",
        "/favicon.ico",
        "/robots.txt",
        "/health",
        "/ready",
        "/metrics",
    ):
        c = classify_surface(f"https://e.com{path}")
        assert c.label == "low", f"{path} should be low (got {c.label})"


def test_image_extension_low():
    c = classify_surface("https://e.com/uploads/avatar.jpg")
    assert c.label == "low"


def test_swagger_docs_low():
    c = classify_surface("https://e.com/swagger.json")
    assert c.label == "low"


# --------------------------------------------------------------------
# Normal default
# --------------------------------------------------------------------

def test_unmatched_path_is_normal():
    c = classify_surface("https://e.com/products/42")
    assert c.label == "normal"
    assert c.depth_multiplier == 1.0


# --------------------------------------------------------------------
# OpenAPI metadata overrides
# --------------------------------------------------------------------

def test_x_internal_promotes_to_critical():
    c = classify_surface(
        "https://e.com/products/42",
        openapi_metadata={"x-internal": True},
    )
    assert c.label == "critical"


def test_x_strix_priority_honored():
    c = classify_surface(
        "https://e.com/random/path",
        openapi_metadata={"x-strix-priority": "high"},
    )
    assert c.label == "high"


def test_invalid_priority_label_ignored():
    """Garbage in x-strix-priority shouldn't crash."""
    c = classify_surface(
        "https://e.com/admin",
        openapi_metadata={"x-strix-priority": "nonsense"},
    )
    # Falls through to critical-path matcher
    assert c.label == "critical"


# --------------------------------------------------------------------
# SAST sensitive override
# --------------------------------------------------------------------

def test_sast_sensitive_promotes_normal_to_high():
    c = classify_surface(
        "https://e.com/products/42",
        sast_taints_sensitive=True,
    )
    assert c.label == "high"


def test_sast_sensitive_overrides_low_path():
    """A static-looking path that SAST says touches sensitive data
    should NOT be low."""
    c = classify_surface(
        "https://e.com/static/dump.json",  # would otherwise be low
        sast_taints_sensitive=True,
    )
    assert c.label != "low"


# --------------------------------------------------------------------
# Robustness
# --------------------------------------------------------------------

def test_empty_surface_returns_normal():
    c = classify_surface("")
    assert c.label == "normal"


def test_bare_path_input():
    c = classify_surface("/admin/foo")
    assert c.label == "critical"


def test_depth_multiplier_for_convenience():
    assert depth_multiplier_for("https://e.com/admin") == 3.0
    assert depth_multiplier_for("https://e.com/static/x.css") == 0.3
    assert depth_multiplier_for("https://e.com/api/foo") == 1.0
