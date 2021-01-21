#ifndef ALGORAND_H
#define ALGORAND_H

#include <memory>

#define RAPIDJSON_HAS_STDSTRING 1
#include "rapidjson/document.h"

#include <msgpack.hpp>

std::ostream& operator<<(std::ostream& os, const rapidjson::Value&);
std::string json_to_string(const rapidjson::Value&);

struct JsonResponse {
  int status;
  std::unique_ptr<rapidjson::Document> json;
  rapidjson::Value& operator[](const std::string& name) const {
    return (*json)[name];
  }
};
std::ostream& operator<<(std::ostream& os, const JsonResponse& jr);

typedef std::vector<unsigned char> bytes;

class Address {
public:
  Address();                    // Constructs the ZERO address
  // Address(const Address&);

  Address(std::string b32form);
  Address(bytes public_key);
  std::string as_string;
  bytes public_key;
  bool is_zero() const;
private:
  Address(std::string s, bytes with_csum);
  Address(bytes public_key, bytes with_csum);
};
inline bool operator==(const Address& lhs, const Address& rhs) {
  return lhs.as_string == rhs.as_string && lhs.public_key == rhs.public_key;
}
inline bool operator!=(const Address& lhs, const Address& rhs) {
  return !(lhs == rhs);
}

class Account {
public:
  Account(std::string address);
  Account(Address address);
  Account(bytes public_key, bytes secret_key);
  Account(std::pair<bytes,bytes> key_pair);

  static Account from_mnemonic(std::string mnemonic);
  static std::pair<bytes,bytes> generate_keys();
  static std::pair<bytes,bytes> generate_keys(bytes seed);

  std::string mnemonic() const;
  bytes seed() const;

  const bytes public_key() const { return address.public_key; }
  const Address address;
  const bytes secret_key;       // may or may not have.
};
std::ostream& operator<<(std::ostream& os, const Account& acct);

/* We use a single transaction class to represent all transaction
   types.  While it might seem natural to have Payment, AssetCreate
   and so on as subclasses, it would complicate msgpacking. msgpack
   libraries generally do not "omitempty" (as we must to be compatible
   with algod/spec), so we need to use the lower-level packing
   routines.  It seems easier to consolidate that in one place than to
   create an interface for subclasses that would allow them to a)
   report how many keys they intend to populate and b) return the
   pairs, and c) sort them before packing them from the top.

   We'd then also need some sort of "virtual constructor" pattern to
   unpack Transactions into the right subclass.

   PS. This more closely models the implementation in algod.
 */
class Transaction {
  Transaction(Address sender, std::string tx_type);
public:
  static Transaction payment(Address sender,

                             Address receiver, uint64_t amount, bytes close_to,

                             uint64_t fee,
                             uint64_t first_valid, uint64_t last_valid,
                             std::string genesis_id, bytes genesis_hash,
                             bytes lease, bytes note, Address rekey_to);

  static Transaction key_registration(Address sender,

                                      bytes vote_pk,
                                      bytes selection_pk,
                                      uint64_t vote_first,
                                      uint64_t vote_last,
                                      uint64_t vote_key_dilution,
                                      bool nonparticipation,

                                      uint64_t fee,
                                      uint64_t first_valid, uint64_t last_valid,
                                      std::string genesis_id, bytes genesis_hash,
                                      bytes lease, bytes note, Address rekey_to);

  // Field names and sections are taken from:
  //  https://developer.algorand.org/docs/reference/transactions/
  // Header
  uint64_t fee = 1000;          // required parameter, but a nice safety
  uint64_t first_valid;
  bytes genesis_hash;
  uint64_t last_valid;
  Address sender;
  std::string tx_type;
  std::string genesis_id;
  bytes group;
  bytes lease;
  bytes note;
  Address rekey_to;
  // Payment
  Address receiver;
  uint64_t amount = 0;
  bytes close_remainder_to;
  // Key Registration
  bytes vote_pk;
  bytes selection_pk;
  uint64_t vote_first = 0;
  uint64_t vote_last = 0;
  uint64_t vote_key_dilution = 0;
  bool nonparticipation = false;
  // Asset Configuration
  // Asset Config
  // Asset Transfer
  // Asset Freeze
  // Application Call
  // Compact Cert

  template <typename Stream>
  msgpack::packer<Stream>& pack(msgpack::packer<Stream>& o) const;

  int key_count() const;
  bytes encode() const;
};

namespace msgpack {
  MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS) {
    namespace adaptor {
      template<>
      struct pack<Transaction> {
        template <typename Stream>
        packer<Stream>&
        operator()(msgpack::packer<Stream>& o, Transaction const& v) const {
          // We don't use the MSGPACK_DEFAULT_MAP macro because we need
          // to "omitempty" for compatibility. That requires counting
          // keys first, to size the map, and then packing them (in
          // lexographical order).
          return v.pack<Stream>(o);
        }
      };
    } // namespace adaptor
  } // MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS)
}


class Algorand {
public:
  /**
   * @brief Initialize the client. Reads ALGOD_ADDRESS, ALGOD_TOKEN
   * from environment.
   */
  Algorand();

  bool healthy(void);
  std::string metrics(void);
  JsonResponse account(std::string address);
  JsonResponse transactions_pending(std::string address, unsigned max = 0);
  JsonResponse application(std::string id);
  JsonResponse asset(std::string id);
  JsonResponse block(uint64_t round);
  JsonResponse catchup(std::string catchpoint);
  JsonResponse abort_catchup(std::string catchpoint);
  JsonResponse supply();
  JsonResponse register_participation_key(std::string address, uint64_t fee, uint64_t key_dilution, bool no_wait, uint64_t lv);
  JsonResponse status();
  JsonResponse status_after(uint64_t block);

  JsonResponse teal_compile(std::string source);
  JsonResponse teal_dryrun(rapidjson::Value& request);

  JsonResponse transaction_submit(std::string raw);
  JsonResponse transaction_params();
  JsonResponse transaction_pending(std::string txid = "");

private:
  std::string algod_address;    // Acts as prefix for REST requests
  std::string algod_token;      // Authorizes API access
  std::string kmd_address;      // Acts as prefix for REST requests
  std::string kmd_token;        // Authorizes API access
  std::string indexer_address;  // Acts as prefix for REST requests
  std::string indexer_token;    // Authorizes API access

public:
  /**
   * @brief Return the requested information from the API using method
   * @param route API route.
   * @param method HTTP method to make the request with
   * @param request_body raw bytes to be sent as body of request
   * @return JsonResponse with the status code and JSON value from response
   */
  JsonResponse api(const std::string& route,
                   const std::string& method,
                   const std::string& request_body = "");

  /**
   * @brief Return the requested information from the API using a GET
   * @param route API route.
   * @return string containing the requested information.
   */
  JsonResponse get(const std::string& route);

  /**
   * @brief Return the requested information from the API using a POST
   * @param route API route.
   * @param body Raw bytes to send as body. "" means no body.
   * @return string containing the requested information.
   */
  JsonResponse post(const std::string& route, const std::string& body = "");
};

#endif
