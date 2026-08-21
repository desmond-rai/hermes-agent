from plugins.memory.honcho.safety import contains_secret, safe_exchange


def test_contains_secret_covers_common_credential_shapes():
    samples = (
        "api_key=credentialvalue123",
        "Authorization: Basic dXNlcjpwYXNzd29yZA==",
        "postgres://user:password@example.com/database",
        "xox" + "b-123456789012-abcdefghijklmnopqrstuvwxyz",
        "AKIAIOSFODNN7EXAMPLE",
        "aws_session_token=longtemporarycredential",
        '{"password":"credentialvalue123"}',
        '{"aws_secret_access_key":"longtemporarycredential"}',
        '{"Authorization":"Basic dXNlcjpwYXNzd29yZA=="}',
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturevalue123",
        "glpat-abcdefghijklmnopqrst",
        "AIzaSyA1234567890abcdefghijklmnopqrst",
        "-----BEGIN PRIVATE KEY-----\nsecret",
    )
    assert all(contains_secret(sample) for sample in samples)


def test_contains_secret_allows_discussion_without_values():
    assert not contains_secret("Rotate the API key and database password")
    assert not contains_secret("Use Basic authentication after approval")


def test_safe_exchange_rejects_either_secret_bearing_side():
    assert not safe_exchange("api_key=credentialvalue123", "done")
    assert not safe_exchange("hello", "xox" + "p-123456789012-abcdefghijklmnopqrstuvwxyz")
    assert safe_exchange("hello", "safe answer")


def test_safe_exchange_rejects_quality_assurance_noise():
    for prompt in (
        "HONCHO_TEST_HERMES_123 Reply exactly: OK",
        "Use honcho_search to find the marker and quote it back.",
        "Are you connected to Composio CLI?",
        "What MCPs are you currently connected to?",
    ):
        assert not safe_exchange(prompt, "done")
    assert safe_exchange("How should memory work across projects?", "Use project rules.")
