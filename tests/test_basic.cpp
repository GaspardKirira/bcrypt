#include <cassert>
#include <iostream>
#include <string>

#define BCRYPT_USE_CRYPT
#include <bcrypt/bcrypt.hpp>

static void test_cost_validation()
{
  assert(bcrypt::is_valid_cost(4));
  assert(bcrypt::is_valid_cost(12));
  assert(bcrypt::is_valid_cost(31));

  assert(!bcrypt::is_valid_cost(3));
  assert(!bcrypt::is_valid_cost(32));
}

static void test_generate_salt_format()
{
  auto r = bcrypt::generate_salt(12, "2b");
  assert(r.ok);
  assert(!r.value.empty());

  // Expected prefix: $2b$12$
  assert(r.value.size() >= 7);
  assert(r.value.rfind("$2b$12$", 0) == 0);

  // Full salt length should be 29: $ + 2 + $ + 2 + $ + 22
  assert(r.value.size() == 29);
}

static void test_hash_and_verify_roundtrip()
{
  bcrypt::HashOptions opt{};
  opt.cost = 10;
  opt.variant = "2b";

  auto h = bcrypt::hash_password("secret_password", opt);
  assert(h.ok);
  assert(!h.value.empty());

  // Typically 60 chars for bcrypt hash.
  assert(h.value.size() >= 29);
  assert(h.value.rfind("$2", 0) == 0);

  auto ok1 = bcrypt::verify_password("secret_password", h.value);
  assert(ok1.ok);

  auto ok2 = bcrypt::verify_password("wrong_password", h.value);
  assert(!ok2.ok);
  // No backend error, just mismatch
  assert(ok2.error.empty());
}

static void test_hash_with_salt()
{
  auto salt = bcrypt::generate_salt(10, "2b");
  assert(salt.ok);

  auto h = bcrypt::hash_password_with_salt("hello", salt.value);
  assert(h.ok);
  assert(h.value.rfind("$2b$10$", 0) == 0);

  auto v = bcrypt::verify_password("hello", h.value);
  assert(v.ok);
}

static void test_invalid_inputs()
{
  // Empty password
  {
    auto r = bcrypt::hash_password("");
    assert(!r.ok);
    assert(!r.error.empty());
  }

  // Invalid salt
  {
    auto r = bcrypt::hash_password_with_salt("pw", "not-a-salt");
    assert(!r.ok);
    assert(!r.error.empty());
  }

  // Invalid existing hash
  {
    auto r = bcrypt::verify_password("pw", "not-a-hash");
    assert(!r.ok);
    assert(!r.error.empty());
  }

  // Invalid cost
  {
    auto r = bcrypt::generate_salt(2, "2b");
    assert(!r.ok);
    assert(!r.error.empty());
  }

  // Invalid variant
  {
    auto r = bcrypt::generate_salt(12, "xx");
    assert(!r.ok);
    assert(!r.error.empty());
  }
}

int main()
{
  test_cost_validation();
  test_generate_salt_format();
  test_hash_and_verify_roundtrip();
  test_hash_with_salt();
  test_invalid_inputs();

  std::cout << "[bcrypt] all tests passed\n";
  return 0;
}
