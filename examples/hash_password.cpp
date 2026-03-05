#include <iostream>
#include <string>

#define BCRYPT_USE_CRYPT
#include <bcrypt/bcrypt.hpp>

/*
  Example: hashing a password using bcrypt.
*/

int main()
{
  std::string password = "my_secret_password";

  bcrypt::HashOptions opt;
  opt.cost = 12;
  opt.variant = "2b";

  auto result = bcrypt::hash_password(password, opt);

  if (!result.ok)
  {
    std::cout << "Hash failed: " << result.error << "\n";
    return 1;
  }

  std::cout << "Password hash:\n";
  std::cout << result.value << "\n";

  return 0;
}
