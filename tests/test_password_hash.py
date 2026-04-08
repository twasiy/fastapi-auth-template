from app.utils.password_hash import hash_password, verify_password, needs_rehash


class TestHashPassword:
    def test_returns_string(self):
        result = hash_password("MySecurePassword!")
        assert isinstance(result, str)

    def test_hash_is_argon2id(self):
        result = hash_password("SomePassword1")
        assert result.startswith("$argon2id$")

    def test_same_password_produces_different_hashes(self):
        """Salt must be random — two hashes of the same password must differ."""
        h1 = hash_password("SamePassword!")
        h2 = hash_password("SamePassword!")
        assert h1 != h2

    def test_empty_string_still_hashes(self):
        result = hash_password("")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_unicode_password_hashes(self):
        result = hash_password("পাসওয়ার্ড১২৩")
        assert isinstance(result, str)


class TestVerifyPassword:
    def test_correct_password_returns_true(self):
        pw = "CorrectHorseBatteryStaple"
        hashed = hash_password(pw)
        assert verify_password(pw, hashed) is True

    def test_wrong_password_returns_false(self):
        hashed = hash_password("CorrectPassword!")
        assert verify_password("WrongPassword!", hashed) is False

    def test_empty_password_vs_non_empty_hash_returns_false(self):
        hashed = hash_password("ActualPassword!")
        assert verify_password("", hashed) is False

    def test_invalid_hash_returns_false(self):
        """Should not raise — must gracefully return False."""
        assert verify_password("anything", "not-a-valid-hash") is False

    def test_case_sensitive(self):
        hashed = hash_password("password")
        assert verify_password("Password", hashed) is False
        assert verify_password("PASSWORD", hashed) is False

    def test_whitespace_matters(self):
        hashed = hash_password("password")
        assert verify_password("password ", hashed) is False
        assert verify_password(" password", hashed) is False


class TestNeedsRehash:
    def test_fresh_hash_does_not_need_rehash(self):
        hashed = hash_password("SomePassword!")
        assert needs_rehash(hashed) is False

    def test_returns_bool(self):
        hashed = hash_password("SomePassword!")
        result = needs_rehash(hashed)
        assert isinstance(result, bool)
