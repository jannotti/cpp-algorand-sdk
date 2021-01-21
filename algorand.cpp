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

Transaction::Transaction(Address sender, std::string tx_type) :
  sender(sender), tx_type(tx_type) { }

Transaction
Transaction::payment(Address sender,
                     Address receiver, uint64_t amount, bytes close_to,
                     uint64_t fee,
                     uint64_t first_valid, uint64_t last_valid,
                     std::string genesis_id, bytes genesis_hash,
                     bytes lease, bytes note, Address rekey_to) {
  Transaction t = Transaction(sender, "pay");

  t.receiver = receiver;
  t.amount = amount;
  t.close_remainder_to = close_to;

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
  keys += is_present(close_remainder_to);

  keys += is_present(vote_pk);
  keys += is_present(selection_pk);
  keys += is_present(vote_first);
  keys += is_present(vote_last);
  keys += is_present(vote_key_dilution);
  keys += is_present(nonparticipation);

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

  o.pack_map(key_count());
  if (is_present(amount)) { o.pack("amt"); o.pack(amount); }
  if (is_present(close_remainder_to)) { o.pack("close"); o.pack(close_remainder_to); }
  if (is_present(fee)) { o.pack("fee"); o.pack(fee); }
  if (is_present(first_valid)) { o.pack("fv"); o.pack(first_valid); }
  if (is_present(genesis_hash)) { o.pack("gh"); o.pack(genesis_hash); }
  if (is_present(genesis_id)) { o.pack("gen"); o.pack(genesis_id); }
  if (is_present(group)) { o.pack("grp"); o.pack(group); }
  if (is_present(last_valid)) { o.pack("lv"); o.pack(last_valid); }
  if (is_present(lease)) { o.pack("lx"); o.pack(lease); }
  if (is_present(nonparticipation)) { o.pack("nonpart"); o.pack(nonparticipation); }
  if (is_present(note)) { o.pack("note"); o.pack(note); }
  if (is_present(receiver)) { o.pack("rcv"); o.pack(receiver.public_key); }
  if (is_present(rekey_to)) { o.pack("rekey"); o.pack(rekey_to.public_key); }
  if (is_present(selection_pk)) { o.pack("selkey"); o.pack(selection_pk); }
  if (is_present(sender)) { o.pack("snd"); o.pack(sender.public_key); }
  if (is_present(tx_type)) { o.pack("type"); o.pack(tx_type); }
  if (is_present(vote_first)) { o.pack("votefst"); o.pack(vote_pk); }
  if (is_present(vote_key_dilution)) { o.pack("votekd"); o.pack(vote_pk); }
  if (is_present(vote_last)) { o.pack("votelst"); o.pack(vote_pk); }
  if (is_present(vote_pk)) { o.pack("votekey"); o.pack(vote_pk); }
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
