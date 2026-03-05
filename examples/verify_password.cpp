#include <iostream>
#include <string>

#define BCRYPT_USE_CRYPT
#include <bcrypt/bcrypt.hpp>

/*
  Example: verifying a password against a stored bcrypt hash.
*/

int main()
{
  std::string password = "my_secret_password";

  // Normally this would come from your database
  std::string stored_hash;

  auto hash_result = bcrypt::hash_password(password);

  if (!hash_result.ok)
  {
    std::cout << "Hash failed\n";
    return 1;
  }

  stored_hash = hash_result.value;

  auto verify = bcrypt::verify_password(password, stored_hash);

  if (verify.ok)
  {
    std::cout << "Password verified\n";
  }
  else
  {
    std::cout << "Password mismatch\n";
  }

  return 0;
}
