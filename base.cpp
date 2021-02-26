#include "base.h"

#define B64DIGITS "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

std::string b64_encode(const bytes& in, bool padded) {
  std::string out;
  out.reserve(4 + (4*in.size()/3));

  int val = 0;
  int bits = 0;
  for (auto c : in) {
    val = (val << 8) + c;
    bits += 8;
    while (bits >= 6) {
      out.push_back(B64DIGITS[(val>>(bits-6))&0x3F]);
      bits -= 6;
    }
  }
  if (bits > 0)
    out.push_back(B64DIGITS[(val<<(6-bits))&0x3F]);
  while (padded && out.size() % 4)
    out.push_back('=');
  return out;
}

std::vector<int> decode64_digits() {
  std::vector<int> table(256, -1);
  for (int i=0; i<64; i++)
    table[B64DIGITS[i]] = i;
  return table;
}


bytes b64_decode(const std::string &in) {
  static std::vector<int> dd = decode64_digits();

  bytes out;
  out.reserve(3*in.size()/4);

  int val = 0;
  int bits = 0;
  for (auto c : in) {
    if (dd[c] == -1)             // bail on any non-b64 digit
      break;
    val = (val << 6) + dd[c];
    bits += 6;
    if (bits >= 8) {
      out.push_back(char((val>>(bits-8))&0xFF));
      bits -= 8;
    }
  }
  return out;
}

// Surely I should write an implementation that avoids the almost
// cutnpaste job here.


#define B32DIGITS "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

std::string b32_encode(const bytes& in) {
  std::string out;
  out.reserve(8 + (8*in.size()/5));

  int val = 0;
  int bits = 0;
  for (auto c : in) {
    val = (val << 8) + c;
    bits += 8;
    while (bits >= 5) {
      out.push_back(B32DIGITS[(val>>(bits-5))&0x1F]);
      bits -= 5;
    }
  }
  if (bits > 0)
    out.push_back(B32DIGITS[(val<<(5-bits))&0x1F]);
  return out;
}

std::vector<int> decode32_digits() {
  std::vector<int> table(256, -1);
  for (int i=0; i<32; i++)
    table[B32DIGITS[i]] = i;
  return table;
}


bytes b32_decode(const std::string &in) {
  static std::vector<int> dd = decode32_digits();

  bytes out;
  out.reserve(5*in.size()/8);

  int val = 0;
  int bits = 0;
  for (auto c : in) {
    if (dd[c] == -1)             // bail on any non-b32 digit
      break;
    val = (val << 5) + dd[c];
    bits += 5;
    if (bits >= 8) {
      out.push_back(char((val>>(bits-8))&0xFF));
      bits -= 8;
    }
  }
  return out;
}

std::vector<uint16_t> b2048_encode(const bytes& in) {
  std::vector<uint16_t> out;
  out.reserve(1+8*in.size()/11);

  unsigned val = 0;
  int bits = 0;
  for (auto b : in) {
    val |= (b << bits);
    bits += 8;
    if (bits >= 11) {
      out.push_back(val & 0x7FF);
      val >>= 11;
      bits -= 11;
    }
  }
  if (bits > 0)
    out.push_back(val & 0x7FF);
  return out;
}

bytes b2048_decode(const std::vector<uint16_t> &in) {
  bytes out;
  out.reserve(1+11*in.size()/8);

  int val = 0;
  int bits = 0;
  for (auto i : in) {
    val |= (i << bits);
    bits += 11;
    while (bits >= 8) {
      out.push_back(val & 0xFF);
      val >>= 8;
      bits -= 8;
    }
  }
  return out;
}
