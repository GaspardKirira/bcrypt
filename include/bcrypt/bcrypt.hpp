/**
 * @file bcrypt.hpp
 * @brief Minimal bcrypt password hashing and verification wrapper for C++.
 *
 * `bcrypt` provides a small, deterministic API for hashing and verifying passwords
 * using the bcrypt format:
 *
 *   $2b$12$<22-char-salt><31-char-hash>
 *
 * Scope:
 * - Generate bcrypt salts (16 bytes) and format them as bcrypt salt strings
 * - Hash passwords with a given cost
 * - Verify passwords against an existing bcrypt hash string
 * - Constant-time string comparison helper for verification
 *
 * Backends:
 * This library is a wrapper and can use one of the following backends:
 *
 * 1) System crypt backend (recommended for Linux):
 *    - Define BCRYPT_USE_CRYPT before including this header.
 *    - Uses `crypt_r` when available, otherwise `crypt`.
 *    - Note: Some systems require linking with -lcrypt.
 *
 * 2) Custom backend (portable):
 *    - Define BCRYPT_CUSTOM_BACKEND and provide:
 *        bool bcrypt_custom_hash(std::string_view password,
 *                                std::string_view salt,
 *                                std::string &out_hash,
 *                                std::string &out_err);
 *
 *        bool bcrypt_custom_verify(std::string_view password,
 *                                  std::string_view existing_hash,
 *                                  bool &out_ok,
 *                                  std::string &out_err);
 *
 * Randomness:
 * - By default, salt generation uses std::random_device as a best-effort source.
 * - For better control, define BCRYPT_CUSTOM_RANDOM and provide:
 *     bool bcrypt_custom_random_bytes(std::uint8_t *dst, std::size_t n);
 *
 * Non-goals (intentionally minimal):
 * - No user database integration
 * - No password policy enforcement
 * - No pepper management
 * - No KDF alternatives (Argon2, scrypt)
 *
 * Security notes:
 * - Prefer a cost of 10-14 depending on your latency budget.
 * - Always store the full bcrypt hash string as returned by hash_password().
 * - Never truncate the stored hash.
 *
 * Header-only. C++17+.
 */

#ifndef BCRYPT_BCRYPT_HPP
#define BCRYPT_BCRYPT_HPP

#include <cstdint>
#include <cstdlib>

#include <algorithm>
#include <array>
#include <chrono>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#if defined(BCRYPT_USE_CRYPT)
// crypt may require -lcrypt depending on distro.
// We only include headers when explicitly enabled.
#if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <cstring>
#include <unistd.h>
#if defined(__linux__)
#include <crypt.h>
#else
// Many BSD/macOS expose crypt in unistd.h, but crypt.h may exist too.
// If crypt.h is missing on your platform, disable BCRYPT_USE_CRYPT and use a custom backend.
#include <crypt.h>
#endif
#endif
#endif

namespace bcrypt
{
  /**
   * @brief Exception type thrown by bcrypt helpers when using throwing APIs.
   */
  class bcrypt_error : public std::runtime_error
  {
  public:
    explicit bcrypt_error(const std::string &msg) : std::runtime_error(msg) {}
  };

  /**
   * @brief Options for hashing a password.
   */
  struct HashOptions
  {
    int cost = 12;              ///< bcrypt cost (work factor), typical range: 10..14
    std::string variant = "2b"; ///< bcrypt variant: "2a", "2b", "2y" (default "2b")
  };

  /**
   * @brief Result for non-throwing APIs.
   */
  struct Result
  {
    bool ok = false;
    std::string value; ///< resulting hash (for hash ops) or extra info
    std::string error; ///< error message
  };

  /**
   * @brief Validate that a bcrypt cost is within a sensible range.
   *
   * Many implementations allow 4..31. Costs above ~16 are often impractical.
   */
  inline bool is_valid_cost(int cost)
  {
    return cost >= 4 && cost <= 31;
  }

  /**
   * @brief Constant-time string equality (best-effort) for verification.
   *
   * @note This compares full strings without early exit. Still depends on compiler behavior.
   */
  inline bool constant_time_equals(std::string_view a, std::string_view b)
  {
    if (a.size() != b.size())
      return false;

    unsigned char diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i)
      diff |= (unsigned char)(a[i] ^ b[i]);
    return diff == 0;
  }

  /**
   * @brief Generate a bcrypt salt string for a given cost.
   *
   * The returned salt has the form:
   *   $2b$12$<22chars>
   *
   * @param cost bcrypt cost
   * @param variant bcrypt variant, default "2b"
   */
  inline Result generate_salt(int cost, std::string_view variant = "2b");

  /**
   * @brief Hash a password with bcrypt using a generated salt.
   *
   * @param password plaintext password
   * @param opt hashing options (cost, variant)
   * @return Result.value is the full bcrypt hash string on success
   */
  inline Result hash_password(std::string_view password, const HashOptions &opt = {});

  /**
   * @brief Hash a password with bcrypt using a provided salt string.
   *
   * Salt must be of the form:
   *   $2b$12$<22chars>
   *
   * @param password plaintext password
   * @param salt bcrypt salt string
   */
  inline Result hash_password_with_salt(std::string_view password, std::string_view salt);

  /**
   * @brief Verify a password against an existing bcrypt hash string.
   *
   * @param password plaintext password
   * @param existing_hash stored bcrypt hash string
   * @return Result.ok is true if verified, false otherwise. Result.error is set for parse/backend failures.
   */
  inline Result verify_password(std::string_view password, std::string_view existing_hash);

  /**
   * @brief Throwing variant of generate_salt().
   */
  inline std::string generate_salt_or_throw(int cost, std::string_view variant = "2b")
  {
    auto r = generate_salt(cost, variant);
    if (!r.ok)
      throw bcrypt_error(r.error);
    return r.value;
  }

  /**
   * @brief Throwing variant of hash_password().
   */
  inline std::string hash_password_or_throw(std::string_view password, const HashOptions &opt = {})
  {
    auto r = hash_password(password, opt);
    if (!r.ok)
      throw bcrypt_error(r.error);
    return r.value;
  }

  /**
   * @brief Throwing variant of verify_password().
   */
  inline bool verify_password_or_throw(std::string_view password, std::string_view existing_hash)
  {
    auto r = verify_password(password, existing_hash);
    if (!r.error.empty() && !r.ok)
      throw bcrypt_error(r.error);
    return r.ok;
  }

  // ----------------------------
  // detail
  // ----------------------------
  namespace detail
  {
    // bcrypt base64 alphabet (not standard base64)
    inline constexpr const char *bcrypt_b64 =
        "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    inline bool fill_random(std::uint8_t *dst, std::size_t n)
    {
#if defined(BCRYPT_CUSTOM_RANDOM)
      return bcrypt_custom_random_bytes(dst, n);
#else
      // Best-effort using std::random_device.
      // Users needing strict crypto randomness should provide BCRYPT_CUSTOM_RANDOM.
      try
      {
        std::random_device rd;
        for (std::size_t i = 0; i < n; ++i)
          dst[i] = (std::uint8_t)(rd() & 0xFF);
        return true;
      }
      catch (...)
      {
        return false;
      }
#endif
    }

    // Encode 16 bytes salt into 22 chars using bcrypt base64 encoding.
    // bcrypt encodes 128-bit salt as 22 chars (no padding).
    inline std::string bcrypt_base64_encode_16(const std::array<std::uint8_t, 16> &in)
    {
      auto enc6 = [](std::uint32_t v) -> char
      {
        return bcrypt_b64[v & 0x3F];
      };

      std::string out;
      out.reserve(22);

      // Process in chunks similar to bcrypt's encoding rules.
      // We build 22 chars from 16 bytes:
      // 16 bytes = 128 bits, 22 * 6 = 132 bits, bcrypt encoding drops extra bits.
      std::uint32_t c1, c2, c3;
      std::size_t i = 0;

      while (i < 16)
      {
        c1 = in[i++];
        out.push_back(enc6(c1 >> 2));
        out.push_back(enc6((c1 & 0x03) << 4));

        if (i >= 16)
          break;

        c2 = in[i++];
        out.back() = enc6(((c1 & 0x03) << 4) | (c2 >> 4));
        out.push_back(enc6((c2 & 0x0F) << 2));

        if (i >= 16)
          break;

        c3 = in[i++];
        out.back() = enc6(((c2 & 0x0F) << 2) | (c3 >> 6));
        out.push_back(enc6(c3 & 0x3F));
      }

      // The above loop can produce slightly more than needed depending on boundaries.
      // Ensure exact 22 chars.
      if (out.size() > 22)
        out.resize(22);
      while (out.size() < 22)
        out.push_back('.'); // deterministic pad if something went wrong (should not happen)

      return out;
    }

    inline std::string two_digits(int x)
    {
      if (x < 0)
        x = 0;
      if (x > 99)
        x = 99;
      const int a = x / 10;
      const int b = x % 10;
      std::string s;
      s.push_back((char)('0' + a));
      s.push_back((char)('0' + b));
      return s;
    }

    inline bool is_bcrypt_hash_like(std::string_view h)
    {
      // Expected at least: $2b$12$ + 53 chars (salt+hash) => 60 total typical.
      // But we accept minimal salt-only for hash_with_salt.
      return h.size() >= 7 && h[0] == '$' && h.find("$2") == 0;
    }

    inline std::string extract_salt_prefix(std::string_view existing_hash)
    {
      // bcrypt salt prefix length is 29:
      // $2b$12$<22chars>  => 4 + 3 + 1 + 22 = 30? Actually:
      // "$" + "2b" + "$" + "12" + "$" + 22 = 1+2+1+2+1+22 = 29
      if (existing_hash.size() < 29)
        return {};
      return std::string(existing_hash.substr(0, 29));
    }

#if defined(BCRYPT_USE_CRYPT)
    inline bool crypt_hash(std::string_view password, std::string_view salt_or_hash, std::string &out_hash, std::string &out_err)
    {
      out_hash.clear();
      out_err.clear();

// Some systems expose crypt_r
#if defined(__linux__)
      struct crypt_data data;
      std::memset(&data, 0, sizeof(data));
      char *res = ::crypt_r(std::string(password).c_str(), std::string(salt_or_hash).c_str(), &data);
#else
      char *res = ::crypt(std::string(password).c_str(), std::string(salt_or_hash).c_str());
#endif

      if (!res)
      {
        out_err = "bcrypt: crypt backend failed";
        return false;
      }

      out_hash = res;
      return true;
    }
#endif

    inline bool backend_hash(std::string_view password, std::string_view salt, std::string &out_hash, std::string &out_err)
    {
#if defined(BCRYPT_CUSTOM_BACKEND)
      return bcrypt_custom_hash(password, salt, out_hash, out_err);
#elif defined(BCRYPT_USE_CRYPT)
      return crypt_hash(password, salt, out_hash, out_err);
#else
      (void)password;
      (void)salt;
      out_err = "bcrypt: no backend enabled (define BCRYPT_USE_CRYPT or BCRYPT_CUSTOM_BACKEND)";
      return false;
#endif
    }

    inline bool backend_verify(std::string_view password, std::string_view existing_hash, bool &out_ok, std::string &out_err)
    {
#if defined(BCRYPT_CUSTOM_BACKEND)
      return bcrypt_custom_verify(password, existing_hash, out_ok, out_err);
#elif defined(BCRYPT_USE_CRYPT)
      std::string computed;
      if (!crypt_hash(password, existing_hash, computed, out_err))
        return false;
      out_ok = constant_time_equals(computed, existing_hash);
      return true;
#else
      (void)password;
      (void)existing_hash;
      out_err = "bcrypt: no backend enabled (define BCRYPT_USE_CRYPT or BCRYPT_CUSTOM_BACKEND)";
      return false;
#endif
    }

  } // namespace detail

  // ----------------------------
  // public API impl
  // ----------------------------

  inline Result generate_salt(int cost, std::string_view variant)
  {
    Result r{};

    if (!is_valid_cost(cost))
    {
      r.ok = false;
      r.error = "bcrypt: invalid cost (expected 4..31)";
      return r;
    }

    if (!(variant == "2a" || variant == "2b" || variant == "2y"))
    {
      r.ok = false;
      r.error = "bcrypt: invalid variant (expected 2a, 2b, or 2y)";
      return r;
    }

    std::array<std::uint8_t, 16> salt{};
    if (!detail::fill_random(salt.data(), salt.size()))
    {
      r.ok = false;
      r.error = "bcrypt: failed to generate random salt bytes";
      return r;
    }

    const std::string salt22 = detail::bcrypt_base64_encode_16(salt);

    // Format: $2b$12$<22>
    std::string out;
    out.reserve(29);
    out.push_back('$');
    out.append(variant.data(), variant.size());
    out.push_back('$');
    out.append(detail::two_digits(cost));
    out.push_back('$');
    out.append(salt22);

    r.ok = true;
    r.value = std::move(out);
    return r;
  }

  inline Result hash_password(std::string_view password, const HashOptions &opt)
  {
    auto salt = generate_salt(opt.cost, opt.variant);
    if (!salt.ok)
      return salt;

    return hash_password_with_salt(password, salt.value);
  }

  inline Result hash_password_with_salt(std::string_view password, std::string_view salt)
  {
    Result r{};

    if (password.empty())
    {
      r.ok = false;
      r.error = "bcrypt: password is empty";
      return r;
    }

    if (!detail::is_bcrypt_hash_like(salt) || salt.size() < 29)
    {
      r.ok = false;
      r.error = "bcrypt: invalid salt format (expected $2x$cc$22chars)";
      return r;
    }

    std::string out_hash;
    std::string err;

    if (!detail::backend_hash(password, salt, out_hash, err))
    {
      r.ok = false;
      r.error = err.empty() ? "bcrypt: hash backend failed" : err;
      return r;
    }

    if (!detail::is_bcrypt_hash_like(out_hash))
    {
      r.ok = false;
      r.error = "bcrypt: backend returned unexpected hash format";
      return r;
    }

    r.ok = true;
    r.value = std::move(out_hash);
    return r;
  }

  inline Result verify_password(std::string_view password, std::string_view existing_hash)
  {
    Result r{};

    if (password.empty())
    {
      r.ok = false;
      r.error = "bcrypt: password is empty";
      return r;
    }

    if (!detail::is_bcrypt_hash_like(existing_hash))
    {
      r.ok = false;
      r.error = "bcrypt: invalid bcrypt hash format";
      return r;
    }

    bool ok = false;
    std::string err;

    if (!detail::backend_verify(password, existing_hash, ok, err))
    {
      r.ok = false;
      r.error = err.empty() ? "bcrypt: verify backend failed" : err;
      return r;
    }

    r.ok = ok;
    if (!ok)
      r.value = "mismatch";
    return r;
  }

} // namespace bcrypt

#endif // BCRYPT_BCRYPT_HPP
