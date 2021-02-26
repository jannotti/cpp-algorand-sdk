#include "algorand.h"

#include <iostream>
#include <sstream>

#include <curl/curl.h>
#include <rapidjson/ostreamwrapper.h>
#include <rapidjson/prettywriter.h>

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

static std::string
maybe_env(std::string name, std::string def = "") {
  const char* found = getenv(name.c_str());
  if (found)
    return found;
  return def;
}

static std::string
require_env(std::string name) {
  const char* found = getenv(name.c_str());
  if (!found) {
    std::cerr << name << " is not set in the environment." << std::endl;
    exit(1);
  }
  return found;
}

AlgodClient::AlgodClient() {
  algod_address = require_env("ALGOD_ADDRESS");
  algod_token = require_env("ALGOD_TOKEN");
  kmd_address = maybe_env("KMD_ADDRESS");
  kmd_token = maybe_env("KMD_TOKEN", algod_token);
  indexer_address = maybe_env("INDEXER_ADDRESS");
  indexer_token = maybe_env("INDEXER_TOKEN", algod_token);
}

bool
AlgodClient::healthy(void) {
  auto resp(get("/health"));
  return resp.status == 200;
}

std::string
AlgodClient::metrics(void) {
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
AlgodClient::account(std::string address) {
  return get("/v2/accounts/" + address + "?format=json");
}

JsonResponse
AlgodClient::transactions_pending(std::string address, unsigned max) {
  return get("/v2/accounts/" + address +
             "/transactions/pending?format=json&max=" + std::to_string(max));
}

JsonResponse
AlgodClient::application(std::string id) {
  return get("/v2/applications/" + id);
}

JsonResponse
AlgodClient::asset(std::string id) {
  return get("/v2/assets/" + id);
}

JsonResponse
AlgodClient::block(uint64_t round) {
  return get("/v2/blocks/" + std::to_string(round) + "?format=json");
}

JsonResponse
AlgodClient::catchup(std::string catchpoint) {
  return post("/v2/catchup/" + catchpoint);
}

JsonResponse
AlgodClient::abort_catchup(std::string catchpoint) {
  return api("/v2/catchup/" + catchpoint, "DELETE");
}

JsonResponse AlgodClient::supply() {
  return get("/v2/ledger/supply");
}

JsonResponse
AlgodClient::register_participation_key(std::string address,
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
AlgodClient::status() {
  return get("/v2/status");
}
JsonResponse
AlgodClient::status_after(uint64_t block) {
  return get("/v2/status/wait-for-block-after/"+std::to_string(block));
}

JsonResponse
AlgodClient::teal_compile(std::string source) {
  return post("/v2/teal/compile", source);
}
JsonResponse
AlgodClient::teal_dryrun(rapidjson::Value& request) {
  return post("/v2/teal/dryrun", json_to_string(request));
}

JsonResponse
AlgodClient::transaction_submit(std::string rawtxn) {
  return post("/v2/transactions", rawtxn);
}

JsonResponse
AlgodClient::transaction_params() {
  return get("/v2/transactions/params");
}
JsonResponse
AlgodClient::transaction_pending(std::string txid) {
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

  curl_easy_setopt(curl, CURLOPT_VERBOSE, !!getenv("CURL_VERBOSE"));

  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method.c_str());

  struct curl_slist *header_slist = NULL;
  for (auto header : headers)
    header_slist = curl_slist_append(header_slist, header.c_str());
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_slist);

  if (request_body.size()) {
    // I'm not sure how CURLOPT_POST interacts with CUSTOMREQUEST, but
    // it's needed to send data. So if another method requires data...?
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, dispense_request);
    curl_easy_setopt(curl, CURLOPT_READDATA, &request_body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, request_body.size());
  }

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
AlgodClient::api(const std::string& route,
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

JsonResponse AlgodClient::get(const std::string& route) {
  return api(route, "GET", "");
}

JsonResponse AlgodClient::post(const std::string& route, const std::string& body) {
  return api(route, "POST", body);
}
