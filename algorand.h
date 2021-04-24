#ifndef ALGORAND_H
#define ALGORAND_H

#include <memory>

#define RAPIDJSON_HAS_STDSTRING 1
#include "rapidjson/document.h"

#include <msgpack.hpp>

std::ostream& operator<<(std::ostream& os, const rapidjson::Value&);
std::string json_to_string(const rapidjson::Value&);

std::string maybe_env(std::string name, std::string def = "");
std::string require_env(std::string name);

struct JsonResponse {
  int status;
  std::unique_ptr<rapidjson::Document> json;
  rapidjson::Value& operator[](const std::string& name) const {
    return (*json)[name];
  }
  bool succeeded() const { return status == 200; }
};
std::ostream& operator<<(std::ostream& os, const JsonResponse& jr);

typedef std::vector<unsigned char> bytes;

class Address {
public:
  Address();                    // Constructs the ZERO address
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
inline bool operator <(const Address& lhs, const Address& rhs ) {
  return lhs.as_string < rhs.as_string;
}

std::ostream& operator<<(std::ostream& os, const Address& addr);


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
  bytes sign(std::string prefix, bytes msg) const;
  bytes sign(bytes msg) const;

  const bytes public_key() const { return address.public_key; }
  const Address address;
  const bytes secret_key;       // empty() if created from an address, not key
};
std::ostream& operator<<(std::ostream& os, const Account& acct);

class SignedTransaction;

class AssetParams {
public:
  uint64_t total = 0;
  uint64_t decimals = 0;
  bool default_frozen = false;
  std::string unit_name;
  std::string asset_name;
  std::string url;
  bytes meta_data_hash;
  Address manager_addr;
  Address reserve_addr;
  Address freeze_addr;
  Address clawback_addr;

  template <typename Stream>
  msgpack::packer<Stream>& pack(msgpack::packer<Stream>& o) const;

  int key_count() const;
};

class StateSchema {
public:
  StateSchema(int, int) : StateSchema() {}
  StateSchema() : ints(0), byte_slices(0) {}
  uint64_t ints = 0;
  uint64_t byte_slices = 0;

  template <typename Stream>
  msgpack::packer<Stream>& pack(msgpack::packer<Stream>& o) const;

  int key_count() const;
};

class LogicSig {
public:
  LogicSig(bytes logic = {}, std::vector<bytes> args = {}, bytes sig = {}) :
    logic(logic), args(args), sig(sig) {}
  bool is_delegated() const { return !logic.empty(); }

  template <typename Stream>
  msgpack::packer<Stream>& pack(msgpack::packer<Stream>& o) const;

  /* Create a new logicsig with the same program, but delegated by the Account. */
  LogicSig sign(Account) const;

  bytes logic;
  std::vector<bytes> args;
  bytes sig;
};

class Subsig {
public:
  Subsig(bytes public_key, bytes secret_key={});

  void update_secret_key(bytes secret_key);
  bytes get_secret_key(void) const;
  template <typename Stream>
  msgpack::packer<Stream>& pack(msgpack::packer<Stream>& o) const;

  bytes public_key;
  bytes signature;

private:
  bytes secret_key;
};

class MultiSig {
public:
  MultiSig(std::vector<Address> addrs={}, uint64_t threshold=0);

  template <typename Stream>
  msgpack::packer<Stream>& pack(msgpack::packer<Stream>& o) const;

  /* Create a new Multisig with the extra signature of Account */
  MultiSig sign(const std::vector<Account>&) const;

  //TODO: Python SDK throws an exception if 
  //there is no public key match for signature
  //I think it's better to return a boolean 
  //but I'm open to suggestions
  bool sign(const Account&);
  bool sign(bytes secret_key);
  bytes address(void) const;
  
  std::vector<Subsig> sigs;
  uint64_t threshold;
  uint64_t version = 1;

private:
  Address public_address;
  void update_address(void);
};

/* We use a single transaction class to represent all transaction
   types.  While it might seem natural to have Payment, AssetCreate
   and so on as subclasses, it would complicate msgpacking. Standard
   msgpack does not "omitempty" (as we must to be compatible with
   algod/spec), so we need to use the lower-level packing routines.
   It seems easier to consolidate that in one place than to create an
   interface for subclasses that would allow them to a) report how
   many keys they intend to populate and b) return the pairs, and c)
   sort them before packing them from the top.

   We'd then also need some sort of "virtual constructor" pattern to
   unpack Transactions into the right subclass.

   PS. This more closely models the implementation in algod.
 */
class Transaction {
  Transaction(Address sender, std::string tx_type);
public:
  static Transaction payment(Address sender,

                             Address receiver, uint64_t amount, Address close_to,

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

  static Transaction asset_config(Address sender,

                                  uint64_t asset_id, AssetParams asset_params,

                                  uint64_t fee,
                                  uint64_t first_valid, uint64_t last_valid,
                                  std::string genesis_id, bytes genesis_hash,
                                  bytes lease, bytes note, Address rekey_to);

  static Transaction asset_transfer(Address sender,

                                    uint64_t asset_id, uint64_t asset_amount,
                                    Address asset_sender,
                                    Address asset_receiver,
                                    Address asset_close_to,

                                    uint64_t fee,
                                    uint64_t first_valid, uint64_t last_valid,
                                    std::string genesis_id, bytes genesis_hash,
                                    bytes lease, bytes note, Address rekey_to);

  static Transaction asset_freeze(Address sender,

                                  Address freeze_account,
                                  uint64_t freeze_asset,
                                  bool asset_frozen,

                                  uint64_t fee,
                                  uint64_t first_valid, uint64_t last_valid,
                                  std::string genesis_id, bytes genesis_hash,
                                  bytes lease, bytes note, Address rekey_to);

  static Transaction app_call(Address sender,

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
                              bytes lease, bytes note, Address rekey_to);


  SignedTransaction sign(Account) const;
  SignedTransaction sign(LogicSig) const;
  SignedTransaction sign(MultiSig) const;
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
  Address close_to;

  // Key Registration
  bytes vote_pk;
  bytes selection_pk;
  uint64_t vote_first = 0;
  uint64_t vote_last = 0;
  uint64_t vote_key_dilution = 0;
  bool nonparticipation = false;

  // Asset Config
  uint64_t config_asset = 0;
  AssetParams asset_params;

  // Asset Transfer
  uint64_t xfer_asset = 0;
  uint64_t asset_amount = 0;
  Address asset_sender;
  Address asset_receiver;
  Address asset_close_to;

  // Asset Freeze
  uint64_t freeze_asset = 0;
  Address freeze_account;
  bool asset_frozen = false;

  // Application Call
  uint64_t application_id = 0;
  uint64_t on_complete = 0;
  std::vector<Address> accounts;
  bytes approval_program;
  bytes clear_state_program;
  std::vector<bytes> app_arguments;
  std::vector<uint64_t> foreign_apps;
  std::vector<uint64_t> foreign_assets;
  StateSchema globals;
  StateSchema locals;

  template <typename Stream>
  msgpack::packer<Stream>& pack(msgpack::packer<Stream>& o) const;

  int key_count() const;
  bytes encode() const;
};

std::ostream& operator<<(std::ostream& os, const Transaction& txn);

class SignedTransaction {
public:
  SignedTransaction(const Transaction& txn, bytes signature);
  SignedTransaction(const Transaction& txn, LogicSig logic);
  SignedTransaction(const Transaction& txn, MultiSig multi);
  bytes encode() const;

  template <typename Stream>
  msgpack::packer<Stream>& pack(msgpack::packer<Stream>& o) const;
  // Reconsider macro use once we do unpack for Transaction
  // MSGPACK_DEFINE_MAP(sig, txn);
private:
  bytes sig;
  LogicSig lsig;
  MultiSig msig;
  Address signer;
  Transaction txn;
};

namespace msgpack {
  MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS) {
    namespace adaptor {
      template<>
      struct pack<Address> {
        template <typename Stream>
        packer<Stream>&
        operator()(msgpack::packer<Stream>& o, Address const& v) const {
          // We can't use MSGPACK_DEFINE because we don't want to
          // encode an "outer" object here, we just want an Address to
          // encode the public_key as if that was the whole object.
          return o.pack(v.public_key);
        }
      };

      template<>
      struct pack<LogicSig> {
        template <typename Stream>
        packer<Stream>&
        operator()(msgpack::packer<Stream>& o, LogicSig const& v) const {
          return v.pack<Stream>(o);
        }
      };

      template<>
      struct pack<Subsig> {
        template <typename Stream>
        packer<Stream>&
        operator()(msgpack::packer<Stream>& o, Subsig const& v) const {
          return v.pack<Stream>(o);
        }
      };

      template<>
      struct pack<MultiSig> {
        template <typename Stream>
        packer<Stream>&
        operator()(msgpack::packer<Stream>& o, MultiSig const& v) const {
          return v.pack<Stream>(o);
        }
      };

      template<>
      struct pack<Transaction> {
        template <typename Stream>
        packer<Stream>&
        operator()(msgpack::packer<Stream>& o, Transaction const& v) const {
          // We don't use the MSGPACK_DEFINE_MAP macro because we need
          // to "omitempty" for compatibility. That requires counting
          // keys first, to size the map, and then packing them (in
          // lexographical order).
          return v.pack<Stream>(o);
        }
      };

      template<>
      struct pack<SignedTransaction> {
        template <typename Stream>
        packer<Stream>&
        operator()(msgpack::packer<Stream>& o, SignedTransaction const& v) const {
          // We don't use the MSGPACK_DEFINE_MAP macro because
          // Transaction has no unpacking support yet.
          return v.pack<Stream>(o);
        }
      };

      template<>
      struct pack<AssetParams> {
        template <typename Stream>
        packer<Stream>&
        operator()(msgpack::packer<Stream>& o, AssetParams const& v) const {
          // "omitempty" problem, and special Address handling
          return v.pack<Stream>(o);
        }
      };

      template<>
      struct pack<StateSchema> {
        template <typename Stream>
        packer<Stream>&
        operator()(msgpack::packer<Stream>& o, StateSchema const& v) const {
          // "omitempty" problem
          return v.pack<Stream>(o);
        }
      };

    } // namespace adaptor
  } // MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS)
}

class RestClient {
public:
  RestClient(std::string prefix, std::string authorization) :
    prefix(prefix), authorization(authorization) { }
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

protected:
  std::string prefix;
  std::string authorization;
};

class AlgodClient : public RestClient {
public:
  /**
   * @brief Initialize the client. Reads ALGOD_ADDRESS, ALGOD_TOKEN
   * from environment.
   */
  AlgodClient();

  /**
   * @brief Initialize the client with passed address for algod and API token.
   */
  AlgodClient(std::string address, std::string token);

  JsonResponse genesis(void);
  bool healthy(void);
  std::string metrics(void);

  virtual std::string account_url(std::string address);
  JsonResponse account(std::string address);
  JsonResponse account(const Address& addr) { return account(addr.as_string); }
  JsonResponse account(const Account& acct) { return account(acct.address); }

  JsonResponse transactions_pending(std::string address, unsigned max = 0);
  JsonResponse application(std::string id);
  JsonResponse application(uint64_t id) { return asset(std::to_string(id)); }

  virtual std::string asset_url(std::string id);
  JsonResponse asset(std::string id);
  JsonResponse asset(uint64_t id) { return asset(std::to_string(id)); }

  JsonResponse block(uint64_t round);
  JsonResponse catchup(std::string catchpoint);
  JsonResponse abort_catchup(std::string catchpoint);
  JsonResponse supply();
  JsonResponse register_participation_key(std::string address, uint64_t fee, uint64_t key_dilution, bool no_wait, uint64_t lv);
  JsonResponse status();
  JsonResponse status_after(uint64_t block);

  JsonResponse teal_compile(std::string source);
  JsonResponse teal_dryrun(rapidjson::Value& request);

  virtual std::string submit_url();
  JsonResponse submit(std::string raw);
  JsonResponse submit(const SignedTransaction& stxn);
  JsonResponse submit(const std::vector<SignedTransaction> stxn);
  JsonResponse transaction_pending(std::string txid = "");

  virtual std::string params_url();
  JsonResponse params();
};

class IndexerClient : RestClient {
public:
  /**
   * @brief Initialize the client. Reads INDEXER_ADDRESS, INDEXER_TOKEN
   * from environment.
   */
  IndexerClient();
  /**
   * @brief Initialize the client with passed address for indexer and API token.
   */
  IndexerClient(std::string address, std::string token);

  bool healthy(void);
  JsonResponse accounts(uint64_t limit=20, std::string next_page="",
                        uint64_t held_asset=0, uint64_t min_bal=0, uint64_t max_bal=0,
                        uint64_t optedin_app=0,
                        Address auth_addr=Address(), uint64_t as_of=0);
  JsonResponse account(Address addr, uint64_t round=0);
  JsonResponse block(uint64_t round=0);
};
#endif
