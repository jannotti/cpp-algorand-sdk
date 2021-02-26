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

void api_basics() {
  AlgodClient client;
  assert(client.healthy());
  auto metrics = client.metrics();
  assert(metrics.find("ledger_accountsonlinetop_count"));
  assert(metrics.find("algod_ledger_round"));

  auto resp = client.status();
  assert(resp.status == 200);
  assert(resp["last-round"].GetUint64() > 1);

  resp = client.supply();
  assert(resp.status == 200);
  assert(resp["online-money"].GetUint64() > 1);
  assert(resp["total-money"].GetUint64() >= resp["online-money"].GetUint64());

  resp = client.teal_compile("#pragma version 2\nint 1");
  std::cout << resp << std::endl;
  assert(resp.status == 200);
  assert(!strcmp(resp["hash"].GetString(),
                 "YOE6C22GHCTKAN3HU4SE5PGIPN5UKXAJTXCQUPJ3KKF5HOAH646MKKCPDA"));
  assert(!strcmp(resp["result"].GetString(), "AiABASI="));

  resp = client.transaction_params();
  assert(resp.status == 200);
  assert(resp["min-fee"].GetUint64() == 1000);

  resp = client.transaction_pending();
  assert(resp.status == 200);
  resp = client.transaction_pending("junk");
  assert(resp.status != 200);
}

void account(std::string acct) {
  AlgodClient client;
  auto resp = client.account(acct);
  if (!resp.succeeded()) {
    std::cerr << resp["message"].GetString() << std::endl;
    return;
  }

  std::cout <<  *resp.json << std::endl;
  std::cout << client.transactions_pending(acct) << std::endl;
}

void application(std::string app) {
  AlgodClient client;
  std::cout << client.application(app) << std::endl;
}

void asset(std::string asset) {
  AlgodClient client;
  std::cout << client.asset(asset) << std::endl;
}

void end_to_end() {
  AlgodClient client;
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

void signing() {
  auto mn = "advice pudding treat near rule blouse same whisper inner electric "
    "quit surface sunny dismiss leader blood seat clown cost exist "
    "hospital century reform able sponsor";
  Account acct = Account::from_mnemonic(mn);
  Address to{"PNWOET7LLOWMBMLE4KOCELCX6X3D3Q4H2Q4QJASYIEOF7YIPPQBG3YQ5YI"};
  auto fee = 1176;              // make an interface for fee calculation
  auto first_round = 12466;
  auto last_round = 13466;
  auto gh = b64_decode("JgsgCaCTqIaLeVhyL6XlRu3n7Rfk2FxMeK+wRSaQ7dI=");
  auto gen_id = "devnet-v33.0";
  auto note = b64_decode("6gAVR0Nsv5Y=");
  Address close{"IDUTJEUIEVSMXTU4LGTJWZ2UE2E6TIODUKU6UW3FU3UKIQQ77RLUBBBFLA"};
  auto amount = 1000;
  Transaction pay = Transaction::payment(acct.address,
                                         to, amount, close,
                                         fee,
                                         first_round, last_round,
                                         gen_id, gh,
                                         {}, note, {});
  SignedTransaction stxn = pay.sign(acct);

  auto golden =
    "gqNzaWfEQPhUAZ3xkDDcc8FvOVo6UinzmKBCqs0woYSfodlmBMfQvGbeUx3Srxy3d"
    "yJDzv7rLm26BRv9FnL2/AuT7NYfiAWjdHhui6NhbXTNA+ilY2xvc2XEIEDpNJKIJW"
    "TLzpxZpptnVCaJ6aHDoqnqW2Wm6KRCH/xXo2ZlZc0EmKJmds0wsqNnZW6sZGV2bmV"
    "0LXYzMy4womdoxCAmCyAJoJOohot5WHIvpeVG7eftF+TYXEx4r7BFJpDt0qJsds00"
    "mqRub3RlxAjqABVHQ2y/lqNyY3bEIHts4k/rW6zAsWTinCIsV/X2PcOH1DkEglhBH"
    "F/hD3wCo3NuZMQg5/D4TQaBHfnzHI2HixFV9GcdUaGFwgCQhmf0SVhwaKGkdHlwZa"
    "NwYXk";

  assert(golden == b64_encode(stxn.encode()));
  std::cout << "signing pass" << std::endl;
}

void logicsig() {
  bytes program{0x01, 0x20, 0x01, 0x01, 0x22};  // int 1
  Address hash("6Z3C3LDVWGMX23BMSYMANACQOSINPFIRF77H7N3AWJZYV6OH6GWTJKVMXY");
  auto public_key = hash.public_key;

  LogicSig lsig(program);
  // assert(lsig.verify(public_key))
  // assert(lsig.address() == hash)

  std::vector<bytes> args{{0x01, 0x02, 0x03}, {0x04, 0x05, 0x06}};
  lsig = LogicSig(program, args);
  // assert(lsig.verify(public_key))


  Address from("47YPQTIGQEO7T4Y4RWDYWEKV6RTR2UNBQXBABEEGM72ESWDQNCQ52OPASU");
  Address to("PNWOET7LLOWMBMLE4KOCELCX6X3D3Q4H2Q4QJASYIEOF7YIPPQBG3YQ5YI");

  std::string mn = "advice pudding treat near rule blouse same whisper inner "
                   "electric quit surface sunny dismiss leader blood seat clown "
                   "cost exist hospital century reform able sponsor";
  auto fee = 1000;
  auto amount = 2000;
  auto fv = 2063137;

  auto gh = b64_decode("sC3P7e2SdbqKJK0tbiCdK9tdSpbe6XeCGKdoNzmlj0E=");
  auto note = b64_decode("8xMCTuLQ810=");

  Transaction pay = Transaction::payment(from,
                                         to, amount, {},
                                         fee,
                                         fv, fv+1000,
                                         "devnet-v1.0", gh,
                                         {}, note, {});
  auto golden =
    "gqRsc2lng6NhcmeSxAMxMjPEAzQ1NqFsxAUBIAEBIqNzaWfEQE6HXaI5K0lcq50o/"
    "y3bWOYsyw9TLi/oorZB4xaNdn1Z14351u2f6JTON478fl+JhIP4HNRRAIh/I8EWXB"
    "PpJQ2jdHhuiqNhbXTNB9CjZmVlzQPoomZ2zgAfeyGjZ2Vuq2Rldm5ldC12MS4womd"
    "oxCCwLc/t7ZJ1uookrS1uIJ0r211Klt7pd4IYp2g3OaWPQaJsds4AH38JpG5vdGXE"
    "CPMTAk7i0PNdo3JjdsQge2ziT+tbrMCxZOKcIixX9fY9w4fUOQSCWEEcX+EPfAKjc"
    "25kxCDn8PhNBoEd+fMcjYeLEVX0Zx1RoYXCAJCGZ/RJWHBooaR0eXBlo3BheQ";

  args = {{'1','2','3'}, {'4','5','6'}};
  auto acct = Account::from_mnemonic(mn);
  lsig = LogicSig(program, args);
  auto lstx = pay.sign(lsig.sign(acct));

  assert(golden == b64_encode(lstx.encode()));

  std::cout << "logicsig pass" << std::endl;
}

int main(int argc, char** argv) {
  base();
  address();
  mnemonic();
  account();
  transaction();
  signing();
  logicsig();
  api_basics();
  if (argc > 2) {
    if (std::string(argv[1]) == "account") {
      account(argv[2]);
    }
    if (std::string(argv[1]) == "asset") {
      asset(argv[2]);
    }
    if (std::string(argv[1]) == "app") {
      application(argv[2]);
    }
  }
}
