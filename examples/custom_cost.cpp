#include <iostream>
#include <string>

#define BCRYPT_USE_CRYPT
#include <bcrypt/bcrypt.hpp>

/*
  Example: choosing a custom bcrypt cost.
*/

int main()
{
  std::string password = "password123";

  bcrypt::HashOptions opt;
  opt.cost = 14; // stronger but slower
  opt.variant = "2b";

  auto result = bcrypt::hash_password(password, opt);

  if (!result.ok)
  {
    std::cout << "Error: " << result.error << "\n";
    return 1;
  }

  std::cout << "Generated hash:\n";
  std::cout << result.value << "\n";

  return 0;
}
