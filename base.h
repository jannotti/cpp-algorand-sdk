#ifndef BASE_H
#define BASE_H

#include <string>
#include <vector>

typedef std::vector<unsigned char> bytes;

std::string b64_encode(const bytes& in, bool padded = false);
bytes b64_decode(const std::string& in);

std::string b32_encode(const bytes& in);
bytes b32_decode(const std::string& in);

std::vector<uint16_t> b2048_encode(const bytes& in);
bytes b2048_decode(const std::vector<uint16_t> &in);

template<typename T> 
bytes number_to_bytes(T val) {
  bytes byte_array{};

  for(int i=sizeof(val)-(8*sizeof(uint8_t)); i > sizeof(uint8_t)*8; i-=8) {
    auto byte = (val>>i)&0xFF;
    if (0 != byte) {
      byte_array.push_back(byte);
    }
  }
  byte_array.push_back(val&0xFF);

  return byte_array;
}
#endif
