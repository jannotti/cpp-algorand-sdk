#include "algorand.h"
#include "base.h"
#include "mnemonic.h"

#include <iostream>
#include <map>
#include <sstream>
#include <vector>

#include <curl/curl.h>
#include <rapidjson/ostreamwrapper.h>
#include <rapidjson/prettywriter.h>
#include <sodium.h>

typedef std::map<std::string, std::string> string_map;

static std::string
url_escape(const std::string& s) {
  // passing nullptr is something that is done in the curl source for
  // this function, so it seems safe.
  auto encoded = curl_easy_escape(nullptr, s.c_str(), s.length());
  auto as_string(encoded);
  curl_free(encoded);
  return as_string;
}

static std::string
url_parameters(const string_map& map) {
  std::string params;
  for (auto const& kv : map) {
    params += (params.empty() ? "?" : "&");
    params += url_escape(kv.first) + "=" + url_escape(kv.second);
  }
  return params;
}

static int
curl_request(const std::string& url,
             const std::string& method = "GET",
             const std::vector<std::string>& headers = {},
             const std::string& request_body = "",
             const std::string* response_body = nullptr);

std::string
maybe_env(std::string name, std::string def = "") {
  const char* found = getenv(name.c_str());
  if (found)
    return found;
  return def;
}

Address::Address() :
  Address("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ") {
}

// Address::Address(const Address& rhs) :
//   as_string(rhs.as_string),
//   public_key(rhs.public_key) {
// }

bool
Address::is_zero() const {
  return public_key == bytes{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                             0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
}

Address::Address(std::string address) :
  Address(address, b32_decode(address)) {
}

Address::Address(std::string address, bytes with_checksum) :
  as_string(address),
  public_key(bytes{with_checksum.begin(), with_checksum.begin()+32}) {
  assert(as_string.size() == 58);
  assert(public_key.size() == 32);
}

std::string to_hex(const std::string& in) {
  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (size_t i = 0; in.size() > i; i++) {
    ss << std::setw(2) << (int)(unsigned char)in[i] << ':';
  }
  return ss.str();
}
std::string to_hex(const bytes& in) {
  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (size_t i = 0; in.size() > i; i++) {
    ss << std::setw(2) << (int)(unsigned char)in[i] << ':';
  }
  return ss.str();
}

static bytes
checksummed(bytes public_key) {
  bytes copy(public_key);
  auto hash = sha512_256(public_key);
  copy.insert(copy.end(), hash.end()-4, hash.end());
  return copy;
}

Address::Address(bytes public_key) : Address(public_key,  checksummed(public_key)) { }

Address::Address(bytes public_key, bytes checksummed) :
  as_string(b32_encode(checksummed)),
  public_key(public_key) {
  assert(as_string.size() == 58);
  assert(public_key.size() == 32);
}


std::pair<bytes,bytes>
Account::generate_keys(bytes seed) {
  assert(sodium_init() >= 0);
  unsigned char ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
  unsigned char ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];

  crypto_sign_ed25519_seed_keypair(ed25519_pk, ed25519_sk, seed.data());
  auto pub = bytes{ed25519_pk, &ed25519_pk[sizeof(ed25519_pk)]};
  auto sec = bytes{ed25519_sk, &ed25519_sk[sizeof(ed25519_sk)]};
  return std::make_pair(pub, sec);
}

std::pair<bytes,bytes>
Account::generate_keys() {
  assert(sodium_init() >= 0);
  unsigned char ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
  unsigned char ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];

  crypto_sign_ed25519_keypair(ed25519_pk, ed25519_sk);
  auto pub = bytes{ed25519_pk, &ed25519_pk[sizeof(ed25519_pk)]};
  auto sec = bytes{ed25519_sk, &ed25519_sk[sizeof(ed25519_sk)]};
  return std::make_pair(pub, sec);
}

bytes
Account::seed() const {
  unsigned char ed25519_seed[crypto_sign_ed25519_SEEDBYTES];
  crypto_sign_ed25519_sk_to_seed(ed25519_seed, secret_key.data());
  return bytes{ed25519_seed, &ed25519_seed[sizeof(ed25519_seed)]};
}

bytes
Account::sign(std::string prefix, bytes msg) const {
  bytes concat{prefix.begin(), prefix.end()};
  concat.insert(concat.end(), msg.begin(), msg.end());
  return sign(concat);
}

bytes
Account::sign(bytes msg) const {
  unsigned char sig[crypto_sign_ed25519_BYTES];
  crypto_sign_ed25519_detached(sig, 0, msg.data(), msg.size(), secret_key.data());
  auto s = bytes{sig, &sig[sizeof(sig)]};
  return s;

}

Account::Account(std::string address)
  : address(Address(address)) {
}

Account::Account(Address address)
  : address(address) {
}

Account::Account(bytes public_key, bytes secret_key)
  : address(Address(public_key)), secret_key(secret_key)  {
  assert(public_key.size() == crypto_sign_ed25519_PUBLICKEYBYTES);
  assert(secret_key.size() == crypto_sign_ed25519_SECRETKEYBYTES);
}

Account::Account(std::pair<bytes,bytes> key_pair) :
  Account(key_pair.first, key_pair.second) {
}

Account Account::from_mnemonic(std::string m) {
  auto seed = seed_from_mnemonic(m);
  auto keys = generate_keys(seed);
  return Account(keys.first, keys.second);
}

std::string Account::mnemonic() const {
  return mnemonic_from_seed(seed());
}

std::ostream&
operator<<(std::ostream& os, const Account& acct) {
  os << acct.address.as_string;
  return os;
}

bool is_present(bool b) {
  return b;
}
bool is_present(uint64_t u) {
  return u != 0;
}
bool is_present(std::string s) {
  return !s.empty();
}
bool is_present(bytes b) {
  return !b.empty();
}
bool is_present(Address a) {
  return !a.is_zero();
}
bool is_present(LogicSig lsig) {
  return is_present(lsig.logic);
};
bool is_present(AssetParams ap) {
  return ap.key_count() > 0;
};
bool is_present(StateSchema schema) {
  return schema.ints > 0 || schema.byte_slices > 0;
};
bool is_present(Transaction) {
  return true;
};

template <typename E>
bool is_present(std::vector<E> list) {
  for (const auto& e : list)
    if (is_present(e)) return true;
  return false;
}



template <typename Stream, typename V>
int kv_pack(msgpack::packer<Stream>& o, const char* key, V value) {
  if (!is_present(value))
    return 0;
  o.pack(key);
  o.pack(value);
  return 1;
}

LogicSig LogicSig::sign(Account acct) const {
  auto sig = acct.sign("Program", logic);
  return LogicSig{logic, args, sig};
}

template <typename Stream>
msgpack::packer<Stream>& LogicSig::pack(msgpack::packer<Stream>& o) const {
  o.pack_map(1 + is_present(args) + is_present(sig));
  kv_pack(o, "arg", args);
  kv_pack(o, "l", logic);
  kv_pack(o, "sig", sig);
  return o;
}

SignedTransaction::SignedTransaction(const Transaction& txn, bytes signature) :
  sig(signature), txn(txn) { }

SignedTransaction::SignedTransaction(const Transaction& txn, LogicSig logic) :
  lsig(logic), txn(txn) { }

template <typename Stream>
msgpack::packer<Stream>& SignedTransaction::pack(msgpack::packer<Stream>& o) const {
  o.pack_map(2 + is_present(signer)); // one of the sig types, txn, and maybe sgnr
  kv_pack(o, "lsig", lsig);
  kv_pack(o, "sgnr", signer);
  kv_pack(o, "sig", sig);
  kv_pack(o, "txn", txn);
  return o;
}

bytes SignedTransaction::encode() const {
  std::stringstream buffer;
  msgpack::pack(buffer, *this);
  std::string const& s = buffer.str();
  bytes data{s.begin(), s.end()};
  return data;
}


int AssetParams::key_count() const {
  /* count the non-empty fields, for msgpack */
  int keys = 0;
  keys += is_present(total);
  keys += is_present(decimals);
  keys += is_present(default_frozen);
  keys += is_present(unit_name);
  keys += is_present(asset_name);
  keys += is_present(url);
  keys += is_present(meta_data_hash);
  keys += is_present(manager_addr);
  keys += is_present(reserve_addr);
  keys += is_present(freeze_addr);
  keys += is_present(clawback_addr);
  return keys;
}

template <typename Stream>
msgpack::packer<Stream>& AssetParams::pack(msgpack::packer<Stream>& o) const {
  o.pack_map(key_count());
  /* ordering is semantically ugly, but must be lexicographic */
  kv_pack(o, "an", asset_name);
  kv_pack(o, "au", url);
  kv_pack(o, "c", clawback_addr.public_key);
  kv_pack(o, "dc", decimals);
  kv_pack(o, "df", default_frozen);
  kv_pack(o, "f", freeze_addr);
  kv_pack(o, "m", manager_addr);
  kv_pack(o, "r", reserve_addr);
  kv_pack(o, "t", total);
  kv_pack(o, "un", unit_name);
  return o;
}

int StateSchema::key_count() const {
  /* count the non-empty fields, for msgpack */
  int keys = 0;
  keys += is_present(ints);
  keys += is_present(byte_slices);
  return keys;
}

template <typename Stream>
msgpack::packer<Stream>& StateSchema::pack(msgpack::packer<Stream>& o) const {
  o.pack_map(key_count());
  kv_pack(o, "nui", ints);
  kv_pack(o, "nbs", byte_slices);
  return o;
}

Transaction::Transaction(Address sender, std::string tx_type) :
  sender(sender), tx_type(tx_type) { }

Transaction
Transaction::payment(Address sender,
                     Address receiver, uint64_t amount, Address close_to,
                     uint64_t fee,
                     uint64_t first_valid, uint64_t last_valid,
                     std::string genesis_id, bytes genesis_hash,
                     bytes lease, bytes note, Address rekey_to) {
  Transaction t = Transaction(sender, "pay");

  t.receiver = receiver;
  t.amount = amount;
  t.close_to = close_to;

  t.fee = fee;
  t.first_valid = first_valid;
  t.last_valid = last_valid;

  t.genesis_id = genesis_id;
  t.genesis_hash = genesis_hash;
  t.lease = lease;
  t.note = note;
  t.rekey_to = rekey_to;
  return t;
}

Transaction
Transaction::asset_config(Address sender,

                          uint64_t asset_id, AssetParams asset_params,

                          uint64_t fee,
                          uint64_t first_valid, uint64_t last_valid,
                          std::string genesis_id, bytes genesis_hash,
                          bytes lease, bytes note, Address rekey_to) {
  Transaction t = Transaction(sender, "acfg");

  t.config_asset = asset_id;
  t.asset_params = asset_params;

  t.fee = fee;
  t.first_valid = first_valid;
  t.last_valid = last_valid;

  t.genesis_id = genesis_id;
  t.genesis_hash = genesis_hash;
  t.lease = lease;
  t.note = note;
  t.rekey_to = rekey_to;
  return t;
}

Transaction Transaction::asset_transfer(Address sender,

                                        uint64_t asset_id, uint64_t asset_amount,
                                        Address asset_sender,
                                        Address asset_receiver,
                                        Address asset_close_to,

                                        uint64_t fee,
                                        uint64_t first_valid, uint64_t last_valid,
                                        std::string genesis_id, bytes genesis_hash,
                                        bytes lease, bytes note, Address rekey_to) {
  Transaction t = Transaction(sender, "axfr");

  t.xfer_asset = asset_id;
  t.asset_amount = asset_amount;
  t.asset_sender = asset_sender;
  t.asset_receiver = asset_receiver;
  t.asset_close_to = asset_close_to;

  t.fee = fee;
  t.first_valid = first_valid;
  t.last_valid = last_valid;

  t.genesis_id = genesis_id;
  t.genesis_hash = genesis_hash;
  t.lease = lease;
  t.note = note;
  t.rekey_to = rekey_to;
  return t;
}

Transaction Transaction::asset_freeze(Address sender,

                                      Address freeze_account,
                                      uint64_t freeze_asset,
                                      bool asset_frozen,

                                      uint64_t fee,
                                      uint64_t first_valid, uint64_t last_valid,
                                      std::string genesis_id, bytes genesis_hash,
                                      bytes lease, bytes note, Address rekey_to) {
  Transaction t = Transaction(sender, "afrz");

  t.freeze_account = freeze_account;
  t.freeze_asset = freeze_asset;
  t.asset_frozen = asset_frozen;

  t.fee = fee;
  t.first_valid = first_valid;
  t.last_valid = last_valid;

  t.genesis_id = genesis_id;
  t.genesis_hash = genesis_hash;
  t.lease = lease;
  t.note = note;
  t.rekey_to = rekey_to;
  return t;
}

Transaction
Transaction::app_call(Address sender,

                      uint64_t application_id,
                      uint64_t on_complete,
                      std::vector<Address> accounts,
                      bytes approval_program, bytes clear_state_program,
                      std::vector<bytes> app_arguments,
                      std::vector<uint64_t> foreign_apps,
                      std::vector<uint64_t> foreign_assets,
                      StateSchema globals, StateSchema locals,

                      uint64_t fee,
                      uint64_t first_valid, uint64_t last_valid,
                      std::string genesis_id, bytes genesis_hash,
                      bytes lease, bytes note, Address rekey_to) {
  Transaction t = Transaction(sender, "appl");

  t.application_id = application_id;
  t.on_complete = on_complete;
  t.accounts = accounts;
  t.approval_program = approval_program;
  t.clear_state_program = clear_state_program;
  t.app_arguments = app_arguments;
  t.foreign_apps = foreign_apps;
  t.foreign_assets = foreign_assets;
  t.globals = globals;
  t.locals = locals;

  t.fee = fee;
  t.first_valid = first_valid;
  t.last_valid = last_valid;

  t.genesis_id = genesis_id;
  t.genesis_hash = genesis_hash;
  t.lease = lease;
  t.note = note;
  t.rekey_to = rekey_to;
  return t;
}

SignedTransaction Transaction::sign(Account acct) const {
  auto sig = acct.sign("TX", encode());
  return SignedTransaction{*this, sig};
}

SignedTransaction Transaction::sign(LogicSig logic) const {
  return SignedTransaction{*this, logic};
}

int Transaction::key_count() const {
  /* count the non-empty fields, for msgpack */
  int keys = 0;
  keys += is_present(fee);
  keys += is_present(first_valid);
  keys += is_present(genesis_hash);
  keys += is_present(last_valid);
  keys += is_present(sender);
  keys += is_present(tx_type);
  keys += is_present(genesis_id);
  keys += is_present(group);
  keys += is_present(lease);
  keys += is_present(note);
  keys += is_present(rekey_to);

  keys += is_present(receiver);
  keys += is_present(amount);
  keys += is_present(close_to);

  keys += is_present(vote_pk);
  keys += is_present(selection_pk);
  keys += is_present(vote_first);
  keys += is_present(vote_last);
  keys += is_present(vote_key_dilution);
  keys += is_present(nonparticipation);

  keys += is_present(config_asset);
  keys += is_present(asset_params);

  keys += is_present(xfer_asset);
  keys += is_present(asset_amount);
  keys += is_present(asset_sender);
  keys += is_present(asset_receiver);
  keys += is_present(asset_close_to);

  keys += is_present(freeze_account);
  keys += is_present(freeze_asset);
  keys += is_present(asset_frozen);

  return keys;
}

template <typename Stream>
msgpack::packer<Stream>& Transaction::pack(msgpack::packer<Stream>& o) const {
  /*
     Canonical Msgpack: maps must contain keys in lexicographic order;
     maps must omit key-value pairs where the value is a zero-value;
     positive integer values must be encoded as "unsigned" in msgpack,
     regardless of whether the value space is semantically signed or
     unsigned; integer values must be represented in the shortest
     possible encoding; binary arrays must be represented using the
     "bin" format family (that is, use the most recent version of
     msgpack rather than the older msgpack version that had no "bin"
     family).
  */

  // Remember, sort these by the key name, not the variable name!
  // kv_pack exists so that these lines can be sorted directly.
  o.pack_map(key_count());
  kv_pack(o, "aamt", asset_amount);
  kv_pack(o, "aclose", asset_close_to);
  kv_pack(o, "afrz", asset_frozen);
  kv_pack(o, "amt", amount);
  kv_pack(o, "apar", asset_params);
  kv_pack(o, "arcv", asset_receiver);
  kv_pack(o, "asnd", asset_sender);
  kv_pack(o, "caid", config_asset);
  kv_pack(o, "close", close_to);
  kv_pack(o, "fadd", freeze_account);
  kv_pack(o, "faid", freeze_asset);
  kv_pack(o, "fee", fee);
  kv_pack(o, "fv", first_valid);
  kv_pack(o, "gen", genesis_id);
  kv_pack(o, "gh", genesis_hash);
  kv_pack(o, "grp", group);
  kv_pack(o, "lv", last_valid);
  kv_pack(o, "lx", lease);
  kv_pack(o, "nonpart", nonparticipation);
  kv_pack(o, "note", note);
  kv_pack(o, "rcv", receiver);
  kv_pack(o, "rekey", rekey_to);
  kv_pack(o, "selkey", selection_pk);
  kv_pack(o, "snd", sender);
  kv_pack(o, "type", tx_type);
  kv_pack(o, "votefst", vote_pk);
  kv_pack(o, "votekd", vote_pk);
  kv_pack(o, "votekey", vote_pk);
  kv_pack(o, "votelst", vote_pk);
  kv_pack(o, "xaid", xfer_asset);

  kv_pack(o, "apid", application_id);
  kv_pack(o, "apan", on_complete);
  kv_pack(o, "apat", accounts);
  kv_pack(o, "apap", approval_program);
  kv_pack(o, "apsu", clear_state_program);
  kv_pack(o, "apaa", app_arguments);
  kv_pack(o, "apfa", foreign_apps);
  kv_pack(o, "apas", foreign_assets);
  kv_pack(o, "apgs", globals);
  kv_pack(o, "apls", locals);


  return o;
}

template msgpack::packer<std::stringstream>&
Transaction::pack<std::stringstream>(msgpack::packer<std::stringstream>& o) const;

bytes Transaction::encode() const {
  std::stringstream buffer;
  msgpack::pack(buffer, *this);
  std::string const& s = buffer.str();
  bytes data{s.begin(), s.end()};
  return data;
}


Algorand::Algorand() {
  algod_address = maybe_env("ALGOD_ADDRESS");
  algod_token = maybe_env("ALGOD_TOKEN");
  kmd_address = maybe_env("KMD_ADDRESS");
  kmd_token = maybe_env("KMD_TOKEN", algod_token);
  indexer_address = maybe_env("INDEXER_ADDRESS");
  indexer_token = maybe_env("INDEXER_TOKEN", algod_token);
}

bool
Algorand::healthy(void) {
  auto resp(get("/health"));
  return resp.status == 200;
}

std::string
Algorand::metrics(void) {
  // Candidate for refactoring to avoid repetition
  std::string response_body;
  int status = curl_request(algod_address + "/metrics", "GET",
                            {"X-Algo-API-Token: "+algod_token},
                            "", &response_body);
  if (status == 200)
    return response_body;
  return "";
}

JsonResponse
Algorand::account(std::string address) {
  return get("/v2/accounts/" + address + "?format=json");
}

JsonResponse
Algorand::transactions_pending(std::string address, unsigned max) {
  return get("/v2/accounts/" + address +
             "/transactions/pending?format=json&max=" + std::to_string(max));
}

JsonResponse
Algorand::application(std::string id) {
  return get("/v2/applications/" + id);
}

JsonResponse
Algorand::asset(std::string id) {
  return get("/v2/assets/" + id);
}

JsonResponse
Algorand::block(uint64_t round) {
  return get("/v2/blocks/" + std::to_string(round) + "?format=json");
}

JsonResponse
Algorand::catchup(std::string catchpoint) {
  return post("/v2/catchup/" + catchpoint);
}

JsonResponse
Algorand::abort_catchup(std::string catchpoint) {
  return api("/v2/catchup/" + catchpoint, "DELETE");
}

JsonResponse Algorand::supply() {
  return get("/v2/ledger/supply");
}

JsonResponse
Algorand::register_participation_key(std::string address,
                                     uint64_t fee,
                                     uint64_t kd,
                                     bool nw,
                                     uint64_t lv) {
  string_map params = {{"fee", std::to_string(fee)},
                       {"key-dilution", std::to_string(kd)},
                       {"no-wait", std::to_string(nw)},
                       {"round-last-valid", std::to_string(lv)}};
  return post("/v2/register-participation-keys/"+address+url_parameters(params));
}
JsonResponse
Algorand::status() {
  return get("/v2/status");
}
JsonResponse
Algorand::status_after(uint64_t block) {
  return get("/v2/status/wait-for-block-after/"+std::to_string(block));
}

JsonResponse
Algorand::teal_compile(std::string source) {
  return post("/v2/teal/compile", source);
}
JsonResponse
Algorand::teal_dryrun(rapidjson::Value& request) {
  return post("/v2/teal/dryrun", json_to_string(request));
}

JsonResponse
Algorand::transaction_submit(std::string rawtxn) {
  return post("/v2/transactions", rawtxn);
}

JsonResponse
Algorand::transaction_params() {
  return get("/v2/transactions/params");
}
JsonResponse
Algorand::transaction_pending(std::string txid) {
  if (txid.empty())
    return get("/v2/transactions/pending");
  return get("/v2/transactions/pending/"+txid);
}

std::ostream&
operator<<(std::ostream& os, const rapidjson::Value& val) {
  rapidjson::OStreamWrapper osw(os);
  rapidjson::PrettyWriter<rapidjson::OStreamWrapper> writer(osw);
  val.Accept(writer);
  return os;
}

std::ostream&
operator<<(std::ostream& os, const JsonResponse& jr) {
  return os << jr.status << std::endl << *jr.json;
}

std::string
json_to_string(const rapidjson::Value& val) {
  std::stringstream ss;
  ss << val;
  return ss.str();
}


static size_t
accumulate_response(void *contents, size_t size, size_t nmemb, std::string *s) {
  size_t len = size*nmemb;
  s->append((char*)contents, len);
  return len;
}

static size_t
dispense_request(char *dest, size_t size, size_t nmemb, std::string* s) {
  size_t len = std::min(s->size(), size*nmemb);
  if (!len)
    return 0;

  memcpy(dest, s->c_str(), len);
  s->erase(0, len);
  return len;
}

static int
curl_request(const std::string& url,
             const std::string& method,
             const std::vector<std::string>& headers,
             const std::string& request_body,
             const std::string* response_body) {
  CURL *curl = curl_easy_init();
  if (!curl)
    return 200;

  std::cout << url << std::endl;
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method.c_str());

  struct curl_slist *header_slist = NULL;
  for (auto header : headers)
    header_slist = curl_slist_append(header_slist, header.c_str());
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_slist);

  curl_easy_setopt(curl, CURLOPT_READFUNCTION, dispense_request);
  curl_easy_setopt(curl, CURLOPT_READDATA, &request_body);

  if (response_body) {
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, accumulate_response);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response_body);
  }

  CURLcode res = curl_easy_perform(curl);
  if (res != CURLE_OK) {
    std::cerr << "curl_easy_perform() failed: "
              << curl_easy_strerror(res) << std::endl;
    assert(false);
  }
  long http_code = 0;
  curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &http_code);

  curl_slist_free_all(header_slist);
  curl_easy_cleanup(curl);
  return http_code;
}

std::unique_ptr<rapidjson::Document>
json_parse(std::string body) {
  auto doc = std::make_unique<rapidjson::Document>();
  doc->Parse(body);
  return doc;
}

JsonResponse
Algorand::api(const std::string& route,
              const std::string& method,
              const std::string& request_body) {
  std::string response_body;
  int status = curl_request(algod_address + route, method,
                            {"Accept: application/json",
                             "X-Algo-API-Token: "+algod_token},
                            request_body, &response_body);
  if (response_body.empty())
    return JsonResponse{status, nullptr};
  return JsonResponse{status, json_parse(response_body)};
}

JsonResponse Algorand::get(const std::string& route) {
  return api(route, "GET", "");
}

JsonResponse Algorand::post(const std::string& route, const std::string& body) {
  return api(route, "POST", body);
}
