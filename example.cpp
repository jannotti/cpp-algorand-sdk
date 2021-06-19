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

void algod_basics() {
  AlgodClient client;

  auto resp = client.genesis();
  assert(resp["alloc"].IsArray());

  assert(client.healthy());
  auto metrics = client.metrics();
  assert(metrics.find("ledger_accountsonlinetop_count"));
  assert(metrics.find("algod_ledger_round"));

  resp = client.status();
  assert(resp.status == 200);
  assert(resp["last-round"].GetUint64() > 1);

  resp = client.supply();
  assert(resp.status == 200);
  assert(resp["online-money"].GetUint64() > 1);
  assert(resp["total-money"].GetUint64() >= resp["online-money"].GetUint64());

  resp = client.teal_compile("#pragma version 2\nint 1");
  if (resp.status != 404) {
    // some algods don't have it configured on
    assert(resp.status == 200);
    assert(!strcmp(resp["hash"].GetString(),
                   "YOE6C22GHCTKAN3HU4SE5PGIPN5UKXAJTXCQUPJ3KKF5HOAH646MKKCPDA"));
    assert(!strcmp(resp["result"].GetString(), "AiABASI="));
  }

  resp = client.params();
  assert(resp.status == 200);
  assert(resp["min-fee"].GetUint64() == 1000);

  resp = client.transaction_pending();
  assert(resp.status == 200);
  resp = client.transaction_pending("junk");
  assert(resp.status != 200);

  std::cout << "algod pass" << std::endl;
}

void account(std::string addr) {
  AlgodClient client;
  auto resp = client.account(addr);
  if (!resp.succeeded()) {
    std::cerr << resp["message"].GetString() << std::endl;
    return;
  }

  std::cout << *resp.json << std::endl;
  resp = client.transactions_pending(addr);
  assert(resp.succeeded());
}

void application(std::string id) {
  AlgodClient client;
  auto resp = client.application(id);
  if (!resp.succeeded()) {
    std::cerr << resp["message"].GetString() << std::endl;
    return;
  }

  std::cout <<  *resp.json << std::endl;
}

void asset(std::string id) {
  AlgodClient client;
  auto resp = client.asset(id);
  if (!resp.succeeded()) {
    std::cerr << resp["message"].GetString() << std::endl;
    return;
  }

  std::cout <<  *resp.json << std::endl;
}

struct Holding {
  uint64_t amount;
  uint64_t assetId;
  Address creator;
  bool frozen;
};
std::unique_ptr<Holding> holding(std::string addr, std::string asa) {
  auto id = std::strtoull(asa.c_str(), 0, 10);
  AlgodClient client;
  auto resp = client.account(addr);
  if (!resp.succeeded()) {
    std::cerr << resp["message"].GetString() << std::endl;
    return 0;
  }
  auto& assets = resp["assets"];
  for (auto asset = assets.Begin(); asset != assets.End(); asset++) {
    auto aid = (*asset)["asset-id"].GetUint64();
    if (aid == id)
      return std::make_unique<Holding>(Holding{
          (*asset)["amount"].GetUint64(),
          (*asset)["asset-id"].GetUint64(),
          Address{(*asset)["creator"].GetString()},
          (*asset)["is-frozen"].GetBool()});
  }
  return 0;
}

bool opted_in(std::string addr, std::string asa) {
  std::unique_ptr<Holding> h = holding(addr, asa);
  return h ? true : false;
}

bool frozen(std::string addr, std::string asa) {
  std::unique_ptr<Holding> h = holding(addr, asa);
  return h->frozen;
}

void end_to_end() {
  AlgodClient client;
  auto resp = client.params();
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

void multisig() {

  //These mnemonics generate the msig_address below.
  //Only use this on the testnet

  auto mnemonic1 = R"(base giraffe believe make tone transfer wrap attend
                      typical dirt grocery distance outside horn also abstract
                      slim ecology island alter daring equal boil absent
                      carpet)";

  auto mnemonic2 = R"(use animal lonely tragic style wealth uniform poverty
                      idle sail rice dutch patient sport start shine
                      stem path client plunge mutual achieve border absent
                      aspect)";

  //Txn Parameters used to generate transaction and compare against
  //known SDK implementation
  const auto fee = 1000;
  const auto amount = 12345;
  const auto fv = 2063137;
  const auto gh = b64_decode("SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=");
  uint8_t thr = 2;
  //Compare C++ msig adress against golden address generated with the
  //Python SDK using the mnemonics above
  const std::string msig_address =         "MZVMI5WFABIGZKZEBEWIWEEFQCUE4HVOBUTTYFOYGXGZVZAJNFD6PVQHX4";
  //Golden Signed Txn string to compare the C++ Multisig implementation against
  //The Signed Txn string was generated using the Python SDK
  //This is to validate checking that a msig txn that has 2 accounts and threshold set to 2
  const auto golden = "gqRtc2lng6ZzdWJzaWeSgqJwa8QgWJVY1ZpifxAnKngvQRBcNlmGzKxZ0zrpRfUM29CwKhChc8RAlKXNe/"
                      "LoBO/5dYck3nFxCIQEMi59iXNQw3I97aZom17puDaU1PV4YfZCKHshh3B8bpTrthULL3RJNaBHFctMCYKi"
                      "cGvEIO8aieWQj80Zyht42hSihjo/HIhlwi3A1lS0vVXSsIDKoXPEQDheWFHzJ7PM3SUUMY0lfue1ZVyKyOS2"
                      "kUJDnHdJ0sf/0SxyqyOnD1M6GffezoqCPSfSh3V9pXVg238PWHjxqQWjdGhyAqF2AaN0eG6Jo2FtdM0wOaNmZ"
                      "WXNA+iiZnbOAB97IaNnZW6sdGVzdG5ldC12MS4womdoxCBIY7UYpLPITsgQ8i1PEIHLD3HwWaesIN7GL39w5Qk"
                      "6IqJsds4AH38Jo3JjdsQgFfpW8g15Q1QuU2BB+kc3hB79ozYEOuARp4KQ9GH8ESSjc25kxCBmasR2xQBQbKskC"
                      "SyLEIWAqE4erg0nPBXYNc2a5AlpR6R0eXBlo3BheQ";

  std::vector<Address> addresses;
  std::vector<Account> accounts;
  accounts.push_back(Account::from_mnemonic(mnemonic1));
  accounts.push_back(Account::from_mnemonic(mnemonic2));
  addresses.push_back(accounts[0].public_key());
  addresses.push_back(accounts[1].public_key());
  MultiSig msig{addresses, thr};

  //Verify Multisig Public Address is expected Address
  assert(msig_address == msig.address());

  //Verify Multisig Txn can be signed and sent to the "to" address
  Address to{"CX5FN4QNPFBVILSTMBA7URZXQQPP3IZWAQ5OAENHQKIPIYP4CESAQ77PJA"};

  Transaction t = Transaction::payment(msig.address(),
                                        to, 12345, {},
                                        fee,
                                        fv,
                                        fv+1000,
                                        "testnet-v1.0",
                                        gh,
                                        {}, {}, {}
                                       );

 //Create signed Multisig Txn, signed by accounts
  auto smsig = t.sign(msig, accounts);
 //Compare signed, encoded, txn string against
 //Golden String generated with the Python SDK
 assert(golden == b64_encode(smsig.encode()));


  /*** Test partial MSIG. 3 Address, signature threshold 2 ***/
  //Golden Signed Txn string to compare the C++ Multisig implementation against
  //The Signed Txn string was generated using the Python SDK
  //This is to validate checking that a msig txn that has 2 accounts and threshold set to 2
  const auto golden_partial = "gqRtc2lng6ZzdWJzaWeTgqJwa8QgWJVY1ZpifxAnKngvQRBcNlmGzKxZ0zrpRfUM2"
                              "9CwKhChc8RA4Y4ADq8wac/03+cDOT0seLGsbP22LOtsfTaIG31LfJIFE2M02j71GR"
                              "vFE10W3E7hTKAqVK2DCpIJZC2FpNgNA4KicGvEIO8aieWQj80Zyht42hSihjo/HIhl"
                              "wi3A1lS0vVXSsIDKoXPEQCeuZ6FWvPUBh+aBfjFoYuzQknXAx4HMxh5p5gXgbjDw99"
                              "p5t606gFr74RLs95UoKqqyEjlXj3u6N4sGaXqpcQWBonBrxCAV+lbyDXlDVC5TYEH6"
                              "RzeEHv2jNgQ64BGngpD0YfwRJKN0aHICoXYBo3R4bomjYW10zTA5o2ZlZc0D6KJmds"
                              "4AH3sho2dlbqx0ZXN0bmV0LXYxLjCiZ2jEIEhjtRiks8hOyBDyLU8QgcsPcfBZp6wg"
                              "3sYvf3DlCToiomx2zgAffwmjcmN2xCAV+lbyDXlDVC5TYEH6RzeEHv2jNgQ64BGngp"
                              "D0YfwRJKNzbmTEIDw/L2BRPw5UV+lNcm7T5QyVsu/+iemhRSSMgsgVjWxwpHR5cGWjcGF5";

  //Compare C++ msig adress against golden address generated with the
  //Python SDK using the mnemonics above
  const std::string msig_address_partial = "HQ7S6YCRH4HFIV7JJVZG5U7FBSK3F376RHU2CRJERSBMQFMNNRYGPBZRMQ";

  addresses.push_back(to);
  MultiSig msig_partial{addresses, thr};
  //Verify Multisig Public Address is expected Address
  assert(msig_address_partial == msig_partial.address());

  //Verify Multisig Txn can be signed and sent to the "to" address
  Transaction t_partial = Transaction::payment(msig_partial.address(),
                                               to, 12345, {},
                                               fee,
                                               fv,
                                               fv+1000,
                                               "testnet-v1.0",
                                               gh,
                                               {}, {}, {}
                                              );

  //Create signed Multisig Txn using a collection of secret_keys.
  //Note this a collection of 2 secret keys 3 can be used with this
  //account but the threshold is only 2
  auto smsig_partial = t_partial.sign(msig_partial, accounts);

  //Compare signed, encoded, txn string against
  //Golden String generated with the Python SDK
  assert(golden_partial == b64_encode(smsig_partial.encode()));

  std::cout << "multisig pass" << std::endl;
}

void indexer_basics() {
  IndexerClient client;
  auto resp = client.accounts();
  std::cout << resp << std::endl;
  Address addr("CKNVTB7DPRZO3MB64RQFPZIHCHCC4GBSTAAJKVQ2SLYNKVYPK4EJFBCQKM");
  resp = client.account(addr, 2);
  std::cout << resp << std::endl;
  resp = client.block(2);
  std::cout << resp << std::endl;
  std::cout << "indexer pass" << std::endl;
}

void sign_send_save(std::string name, const Transaction& txn, const Account& signer, const AlgodClient& client) {
  {
  std::stringstream buffer;
  msgpack::pack(buffer, txn);
  std::ofstream ofs(name+".txn");
  ofs << buffer.str();
  }

  SignedTransaction stxn = txn.sign(signer);

  std::stringstream sbuffer;
  msgpack::pack(sbuffer, stxn);
  std::ofstream sofs(name+".stxn");
  sofs << sbuffer.str();
  auto resp = client.submit(sbuffer.str());
  std::cout << resp << std::endl;
  assert(resp.status == 200);
}

int main(int argc, char** argv) {
  if (argc > 2) {
    int arg = 1;
    auto cmd = std::string(argv[arg++]);
    if (cmd == "account") {
      account(argv[arg++]);
    }
    if (cmd == "asset" || cmd == "asa") {
      asset(argv[arg++]);
    }
    if (cmd == "app" || cmd == "application") {
      application(argv[arg++]);
    }
    if (cmd == "opted-in") {
      assert(argc == 4);
      std::cout << opted_in(argv[arg], argv[arg+1]) << std::endl;
      arg += 2;
    }
    if (cmd == "asset-balance") {
      assert(argc == 4);
      std::unique_ptr<Holding> h = holding(argv[arg], argv[arg+1]);
      arg += 2;
      std::cout << h->amount << std::endl;
    }
    if (cmd == "mnemonic") {
      Account acct = Account::from_mnemonic(argv[arg++]);
      std::cout << acct.address << std::endl;
      account(acct.address.as_string);
    }

    if (cmd == "pay") {
      AlgodClient client;
      auto resp = client.params();
      assert(resp.status == 200);
      const auto& suggested = *resp.json;

      Account snd = Account::from_mnemonic(argv[arg++]);
      Account rcv = Account(argv[arg++]);
      uint64_t amt = std::stol(argv[arg++]);
      Transaction pay =
        Transaction::payment(snd.public_key(), rcv.public_key(),
                             amt, {},
                             suggested["min-fee"].GetUint64(),
                             suggested["last-round"].GetUint64()+1,
                             suggested["last-round"].GetUint64()+1001,
                             suggested["genesis-id"].GetString(),
                             b64_decode(suggested["genesis-hash"].GetString()),
                             {}, {}, {});

      sign_send_save("pay", pay, snd, client);
    }

    if (cmd == "axfer") {
      AlgodClient client;
      auto resp = client.params();
      assert(resp.status == 200);
      const auto& suggested = *resp.json;

      Account snd = Account::from_mnemonic(argv[arg++]);
      Account rcv = Account(argv[arg++]);
      uint64_t asset_id = std::stol(argv[arg++]);
      uint64_t asset_amount = std::stol(argv[arg++]);
      Transaction axfer =
        Transaction::asset_transfer(snd.public_key(),

                                    asset_id,
                                    asset_amount,
                                    {}, // asset_sender
                                    rcv.public_key(),
                                    {}, // asset_close_to,

                                    suggested["min-fee"].GetUint64(),
                                    suggested["last-round"].GetUint64()+1,
                                    suggested["last-round"].GetUint64()+1001,
                                    suggested["genesis-id"].GetString(),
                                    b64_decode(suggested["genesis-hash"].GetString()),
                                    {}, {}, {});

      sign_send_save("axfer", axfer, snd, client);
    }

    if (cmd == "call") {
      AlgodClient client;
      auto resp = client.params();
      assert(resp.status == 200);
      const auto& suggested = *resp.json;

      Account snd = Account::from_mnemonic(argv[arg++]);
      uint64_t app = std::stol(argv[arg++]);
      Transaction call =
        Transaction::app_call(snd.public_key(),
                              app,
                              0,      // on complete
                              {},     // accounts
                              {}, {}, // approval, clear
                              {},     // arguments
                              {},     // apps
                              {},     // assets
                              {}, {}, // globals locals
                              suggested["min-fee"].GetUint64(),
                              suggested["last-round"].GetUint64()+1,
                              suggested["last-round"].GetUint64()+1001,
                              suggested["genesis-id"].GetString(),
                              b64_decode(suggested["genesis-hash"].GetString()),
                              {}, {}, {});

      sign_send_save("call", call, snd, client);
    }

  } else {
    base();
    address();
    mnemonic();
    account();
    transaction();
    signing();
    logicsig();
    multisig();
    algod_basics();
    indexer_basics();
  }
}
