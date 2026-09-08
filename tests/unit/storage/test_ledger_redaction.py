from kraken.storage.ledger import _sanitize_ledger_entry


def test_sanitize_ledger_entry_redacts_flag_like_token():
    entry = "Attempt output: flag{secret_value_123}"
    out = _sanitize_ledger_entry(entry)
    assert "flag{secret_value_123}" not in out
    assert "<redacted_flag_like_token>" in out


def test_sanitize_ledger_entry_preserves_normal_text():
    entry = "Attempt #2: runtime error index out of range"
    out = _sanitize_ledger_entry(entry)
    assert out == entry
