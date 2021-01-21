#include "algorand.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <regex>

#include "base.h"
#include "mnemonic.h"

void debug(std::string str, std::string file) {
    std::ofstream out(file);
    out << str;
    out.close();
}

void base() {
  bytes hello = {'h', 'e', 'l', 'l', 'o'};
  assert("aGVsbG8" == b64_encode(hello));
  assert(hello == b64_decode(b64_encode(hello)));

  assert("NBSWY3DP" == b32_encode(hello));
  assert(hello == b32_decode(b32_encode(hello)));

  std::vector<uint16_t> encoded{1384, 1420, 1457, 55};
  assert(encoded == b2048_encode(hello));
  assert(hello == b2048_decode(b2048_encode(hello)));
  std::cout << "bases passed" << std::endl;
}

void exercise_rest(int argc, char** argv) {
    Algorand client;
  std::cout << client.healthy() << std::endl;
  std::cout << client.metrics() << std::endl;
  if (argc > 1) {
    std::cout << client.account(argv[1]) << std::endl;
    std::cout << client.transactions_pending(argv[1]) << std::endl;
  }
  if (argc > 2) {
    std::cout << client.application(argv[2]) << std::endl;
  }
  if (argc > 3) {
    std::cout << client.asset(argv[3]) << std::endl;
  }
  auto status = client.status();
  std::cout << status << std::endl;
  auto last_round = status["last-round"].GetUint64();
  std::cout << client.block(last_round) << std::endl;
  std::cout << client.supply() << std::endl;

  auto after = client.status_after(last_round+1);
  std::cout << after << std::endl;

  std::cout << client.teal_compile("int 1\nreturn") << std::endl;

  std::cout << client.transaction_params() << std::endl;
  std::cout << client.transaction_pending() << std::endl;
  std::cout << client.transaction_pending("junk") << std::endl;
}

void end_to_end() {
  Algorand client;
  auto resp = client.transaction_params();
  assert(resp.status == 200);
  const auto& suggested = *resp.json;
  std::cout << suggested << std::endl;

  Account from{"LCKVRVM2MJ7RAJZKPAXUCEC4GZMYNTFMLHJTV2KF6UGNXUFQFIIMSXRVM4"};
  std::cout << from.address << std::endl;

  auto keys = Account::generate_keys();
  Account to{keys.first, keys.second};
  std::cout << to.address << std::endl;

  Transaction t = Transaction::payment(from.public_key(),
                                       to.public_key(), 12345, {},
                                       suggested["min-fee"].GetUint64(),
                                       suggested["last-round"].GetUint64()+1,
                                       suggested["last-round"].GetUint64()+1001,
                                       suggested["genesis-id"].GetString(),
                                       b64_decode(suggested["genesis-hash"].GetString()),
                                       {}, {}, {});
  std::stringstream buffer;
  msgpack::pack(buffer, t);
  std::string s = buffer.str();

  {
    std::ofstream ofs("pay.txn");
    ofs << s;
  }

  //auto handle = msgpack::unpack(s.c_str(), s.length());

  //PaymentTx t3 = handle.get().as<PaymentTx>();
  //std::cout << b64_encode(t3.rcv) << std::endl;
}

static
std::string to_hex(const bytes& in) {
  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (size_t i = 0; in.size() > i; i++) {
    ss << std::setw(2) << (int)(unsigned char)in[i] << ':';
  }
  return ss.str();
}

void address() {
  // Address alice("BX65TTOF324PU3IU5IXZ6VFUX3M33ZQ5NOHGLAEBHF5ECHKAWSQWOZXL4I");
  // std::cout << alice << std::endl;
  // Address bob("TDCYVRHYNTAMZVEOIIGWQPU6GYVWOH5JGYBRFM63MALVKMJQXT66IY3RAE");
  // std::cout << bob << std::endl;

  // Address valid("MO2H6ZU47Q36GJ6GVHUKGEBEQINN7ZWVACMWZQGIYUOE3RBSRVYHV4ACJI");
  // Address invalid("MO2H6ZU47Q36GJ6GVHUKGEBEQINN7ZWVACMWZQGIYUOE3RBSRVYHV4ACJG");

  bytes zero = bytes{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  Address by_key(zero);

  bytes one = bytes{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
  Address one_key(one);

  Address by_str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ");

  assert(by_key.public_key == by_str.public_key);
  assert(by_key.as_string == by_str.as_string);
  assert(by_key == by_str);

  assert(one_key.public_key != by_str.public_key);
  assert(one_key.as_string != by_str.as_string);
  assert(one_key != by_str);
  std::cout << "address pass" << std::endl;
}

void mnemonic() {
  /* mnemonics are only about encoding seeds, not keys. */
  bytes zero = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  std::string mnemonic = R"(abandon abandon abandon abandon abandon abandon
                            abandon abandon abandon abandon abandon abandon
                            abandon abandon abandon abandon abandon abandon
                            abandon abandon abandon abandon abandon abandon
                            invest)";
  assert(zero.size() == 32);
  assert(seed_from_mnemonic(mnemonic).size() == 32);
  assert(zero == seed_from_mnemonic(mnemonic));

  auto zmnemonic = mnemonic_from_seed(zero);
  std::regex spaces("\\s+");
  assert(zmnemonic == std::regex_replace(mnemonic, spaces, " "));

  std::string non_zero = R"(abandon abandon abandon abandon abandon abandon
                            abandon abandon abandon abandon abandon abandon
                            abandon abandon abandon abandon abandon abandon
                            abandon abandon abandon abandon zoo     abandon
                            mom)";
  assert(zero != seed_from_mnemonic(non_zero));

  std::cout << "mnemonic pass" << std::endl;
}

void account() {
  auto mnemonic = R"(base giraffe believe make tone transfer wrap attend
                     typical dirt grocery distance outside horn also abstract
                     slim ecology island alter daring equal boil absent
                     carpet)";
  Account account = Account::from_mnemonic(mnemonic);
  Address address("LCKVRVM2MJ7RAJZKPAXUCEC4GZMYNTFMLHJTV2KF6UGNXUFQFIIMSXRVM4");

  assert(account.address == address);

  std::cout << "account pass" << std::endl;
}

void transaction() {
  Address address("7ZUECA7HFLZTXENRV24SHLU4AVPUTMTTDUFUBNBD64C73F3UHRTHAIOF6Q");
  Address receiver("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ");
  auto gh = b64_decode("JgsgCaCTqIaLeVhyL6XlRu3n7Rfk2FxMeK+wRSaQ7dI=");
  Transaction pay = Transaction::payment(address,
                                         receiver, 1000, {},
                                         1000,
                                         1, 100,
                                         "", gh,
                                         {}, bytes{1, 32, 200}, Address{});

  auto golden =
    "iKNhbXTNA+ijZmVlzQPoomZ2AaJnaMQgJgsgCaCTqIaLeVhyL6XlRu3n7Rfk2FxMe"
    "K+wRSaQ7dKibHZkpG5vdGXEAwEgyKNzbmTEIP5oQQPnKvM7kbGuuSOunAVfSbJzHQ"
    "tAtCP3Bf2XdDxmpHR5cGWjcGF5";

  assert(golden == b64_encode(pay.encode()));

  std::cout << "transaction pass" << std::endl;
}

int main(int argc, char** argv) {
  base();
  address();
  mnemonic();
  account();
  transaction();
  // exercise_rest(argc, argv);
}
