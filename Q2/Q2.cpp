#include <iostream>
#include <string>
#include <vector>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <iterator>
#include <algorithm>
#include <sstream>
#include <iomanip>

// Function to decode Base64URL
std::string base64url_decode(const std::string &data) {
    std::string base64 = data;
    std::replace(base64.begin(), base64.end(), '-', '+');
    std::replace(base64.begin(), base64.end(), '_', '/');
    while (base64.size() % 4 != 0) {
        base64 += '=';
    }

    BIO *bio, *b64;
    int decodeLen = (base64.size() * 3) / 4;
    std::vector<char> buffer(decodeLen);

    bio = BIO_new_mem_buf(base64.data(), base64.size());
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    decodeLen = BIO_read(bio, buffer.data(), base64.size());
    BIO_free_all(bio);

    return std::string(buffer.data(), decodeLen);
}

// Function to encode Base64URL
std::string base64url_encode(const std::string &data) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    bio = BIO_new(BIO_s_mem());
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    BIO_write(bio, data.data(), data.size());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    std::string base64(bufferPtr->data, bufferPtr->length);
    std::replace(base64.begin(), base64.end(), '+', '-');
    std::replace(base64.begin(), base64.end(), '/', '_');
    base64.erase(std::remove(base64.begin(), base64.end(), '='), base64.end());

    return base64;
}

// Function to split JWT token
std::tuple<std::string, std::string, std::string> jwt_signature(const std::string &token) {
    size_t first_dot = token.find('.');
    size_t second_dot = token.find('.', first_dot + 1);
    std::string header = token.substr(0, first_dot);
    std::string payload = token.substr(first_dot + 1, second_dot - first_dot - 1);
    std::string signature = token.substr(second_dot + 1);
    return std::make_tuple(header, payload, signature);
}

// Function to generate HMAC-SHA256 signature
std::string generate_hmac_signature(const std::string &header, const std::string &payload, const std::string &key) {
    std::string message = header + "." + payload;
    unsigned char* digest;
    digest = HMAC(EVP_sha256(), key.c_str(), key.length(), (unsigned char*)message.c_str(), message.length(), NULL, NULL);
    return base64url_encode(std::string((char*)digest, SHA256_DIGEST_LENGTH));
}

// Function to brute-force JWT signature
std::string brute_force_jwt(const std::string &token, const std::vector<std::string> &wordlist) {
    auto [header, payload, signature] = jwt_signature(token);

    for (const auto &key : wordlist) {
        std::string computed_signature = generate_hmac_signature(header, payload, key);
        std::printf("Trying key: %s\n", key.c_str());
        if (computed_signature == signature) {
            std::cout << "✅ Found secret key: " << key << std::endl;
            return key;
        }
    }

    std::cout << "❌ Secret key not found." << std::endl;
    return "";
}

int main() {
    // JWT Token
    std::string token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmY3MtYXNzaWdubWVudC0xIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE2NzI1MTE0MDA"
                        "sInJvbGUiOiJ1c2VyIiwiZW1haWwiOiJhcnVuQGlpaXRkLmFjLmluIiwiaGludCI6Imxvd2VyY2FzZS1hbHBoYW51bWVyaWMtbGVuZ3RoLTUifQ.LCIyPHqWAVNLT8BMXw8_69TPkvabp57ZELxpzom8FiI";

    // Generate wordlist: All 5-character lowercase alphanumeric combinations
    std::string chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    std::vector<std::string> wordlist;
    for (char c1 : chars) {
        for (char c2 : chars) {
            for (char c3 : chars) {
                for (char c4 : chars) {
                    for (char c5 : chars) {
                        wordlist.push_back(std::string{c1, c2, c3, c4, c5});
                    }
                }
            }
        }
    }

    // Start brute force attack
    brute_force_jwt(token, wordlist);

    return 0;
}