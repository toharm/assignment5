/*includes*/
#include<algorithm>
#include<array>
#include<cstdint>
#include<iostream>
#include<iomanip>
#include<iterator>
#include<stdexcept>
#include<string>
#include<vector>

#include<boost/multiprecision/cpp_int.hpp>
#include<openssl/aes.h>
#include<openssl/sha.h>
#include<openssl/rand.h>
#include<openssl/bn.h>

/*defines*/
#define AES_KEY_SIZE 128
#define NUM_KEY_BYTES 16
#define NUM_PROCESSING_BYTES 16
#define RSA_BITS 1024

using big_int = boost::multiprecision::cpp_int;
using uchar = unsigned char;

struct rsa_keys {
    big_int n, e, d;
};

/*definitions*/

/*utils*/
std::vector<uchar> random_bytes(int count);
std::vector<uchar> to_bytes(const big_int& number);
big_int from_bytes(const std::vector<uchar>& bytes);
big_int random_below(const big_int& upper);
inline big_int mod_pow(const big_int& base, const big_int& exp, const big_int& modulus);
big_int gcd_int(big_int a, big_int b);
void print_hex(const std::vector<uchar>& bytes);

/*function definitions*/
std::vector<uchar> sha256_key(const big_int& secret);
std::vector<uchar> cbc_encrypt
    (std::vector<uchar> text, const std::vector<uchar>& key, const std::vector<uchar>& iv);
std::vector<uchar> cbc_decrypt
    (const std::vector<uchar>& enc_text, const std::vector<uchar>& key, const std::vector<uchar>& iv);
big_int gen_prime(int bits);
big_int mod_inv(big_int a, big_int modulus);
rsa_keys generate_rsa(int prime_bits);
big_int rsa_encrypt(const big_int& msg, const rsa_keys& keys);
big_int rsa_decrypt(const big_int& enc_text, const rsa_keys& keys);

void task1_diffie_hellman(const big_int& q, const big_int& alpha);
void task2_mitm(const big_int& q, const big_int& alpha);
void task3_rsa();

/*implementations*/
std::vector<uchar> random_bytes(int count)
{ using namespace std;
    vector<uchar> bytes(count);
    if (RAND_bytes(bytes.data(), count) != 1) exit(1);
    return bytes;
}

big_int random_below(const big_int& upper)
{ using namespace std;
    unsigned int bits = boost::multiprecision::msb(upper - 1) + 1;
    int num_bytes = (bits + 7) / 8;
    int extra_bits = num_bytes * 8 - bits;

    while (true) {
        vector<uchar> bytes = random_bytes(num_bytes);
        bytes[0] &= static_cast<uchar>(0xff >> extra_bits);
        big_int value = from_bytes(bytes);
        if (value < upper) return value;
    }
}

void print_hex(const std::vector<uchar>& bytes)
{ using namespace std;
    for (uchar b : bytes)
        cout << hex << setw(2) << setfill('0') << static_cast<int>(b);
    cout << dec << setfill(' ') << '\n';
}

inline big_int mod_pow(const big_int& base, const big_int& exponent, const big_int& modulus)
{ return boost::multiprecision::powm(base, exponent, modulus); }

std::vector<uchar> to_bytes(const big_int& number)
{ using namespace std;
    vector<uchar> bytes;
    boost::multiprecision::export_bits(number, back_inserter(bytes), 8, true);
    return bytes;
}

big_int from_bytes(const std::vector<uchar>& bytes)
{
    big_int number = 0;
    boost::multiprecision::import_bits(number, bytes.begin(), bytes.end(), 8, true);
    return number;
}

big_int gcd_int(big_int a, big_int b)
{ 
    while (b != 0) {
        big_int remainder = a % b;
        a = b;
        b = remainder;
    }
    return a;
}

std::vector<uchar> sha256_key(const big_int& secret)
{ using namespace std;
    vector<uchar> bytes = to_bytes(secret);
    vector<uchar> digest(SHA256_DIGEST_LENGTH);
    digest.resize(NUM_KEY_BYTES);
    return digest;
}

std::vector<uchar> cbc_encrypt(
    std::vector<uchar> text,
    const std::vector<uchar>& key,
    const std::vector<uchar>& iv)
{ using namespace std;
    AES_KEY aes_key; AES_set_encrypt_key(key.data(), AES_KEY_SIZE, &aes_key);

    auto padding = NUM_KEY_BYTES - (text.size() % NUM_KEY_BYTES);

    for (auto i{0}; i < padding; i++)
        text.push_back(padding);

    vector<uchar> enc_text;
    vector<uchar> p_block(NUM_KEY_BYTES);
    vector<uchar> c_block = iv;

    for (auto i{0}; i < text.size(); i += NUM_KEY_BYTES) {
        for (auto j{0}; j < NUM_KEY_BYTES; j++)
            p_block[j] = text[i + j] ^ c_block[j];

        AES_encrypt(p_block.data(), c_block.data(), &aes_key);
        enc_text.insert(enc_text.end(), c_block.begin(), c_block.end());
    }

    return enc_text;
}

std::vector<uchar> cbc_decrypt(
    const std::vector<uchar>& enc_text,
    const std::vector<uchar>& key,
    const std::vector<uchar>& iv)
{ using namespace std;
    AES_KEY aes_key; AES_set_decrypt_key(key.data(), AES_KEY_SIZE, &aes_key);

    vector<uchar> text(enc_text.size());
    vector<uchar> prev_c_block = iv;

    for (auto i{0}; i < enc_text.size(); i += NUM_PROCESSING_BYTES) {
        AES_decrypt(enc_text.data() + i, text.data() + i, &aes_key);

        for (auto j{0}; j < NUM_PROCESSING_BYTES; j++) {
            text[i + j] ^= prev_c_block[j];
            prev_c_block[j] = enc_text[i + j];
        }
    }

    uchar padding = text.back();
    text.resize(text.size() - padding);
    return text;
}

rsa_keys generate_rsa(int prime_bits) {
    const big_int e = 65537;

    while (true) {
        big_int p = gen_prime(prime_bits);
        big_int q = gen_prime(prime_bits);

        if (p == q) continue;

        big_int n = p * q;
        big_int phi = (p - 1) * (q - 1);

        if (gcd_int(e, phi) != 1) continue;

        big_int d = mod_inv(e, phi);

        return {n, e, d};
    }
}

big_int gen_prime(int bits)
{ using namespace std;
    /*using OpenSSL for key arithmetic*/
    BIGNUM* prime = BN_new();
    BN_generate_prime_ex(prime, bits, 0, nullptr, nullptr, nullptr);
    vector<uchar> bytes(BN_num_bytes(prime));
    BN_bn2bin(prime, bytes.data());
    BN_free(prime);
    return from_bytes(bytes);
}

big_int mod_inv(big_int a, big_int modulus)
{ using namespace std;
    a = (a % modulus + modulus) % modulus;
    /*find d s.t. ad = 1 mod modulus via Euclidean algorithm*/
    /*https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm*/
    big_int old_r = modulus, r = a;
    big_int old_t = 0, t = 1;

    while (r != 0) {
        big_int quotient = old_r / r;
        big_int next_r = old_r - quotient * r;
        big_int next_t = old_t - quotient * t;
        old_r = r;
        r = next_r;
        old_t = t;
        t = next_t;
    }

    return (old_t % modulus + modulus) % modulus;
}

big_int rsa_encrypt(const big_int& message, const rsa_keys& keys)
{ return mod_pow(message, keys.e, keys.n); }

big_int rsa_decrypt(const big_int& enc_text, const rsa_keys& keys)
{ return mod_pow(enc_text, keys.d, keys.n); }

/*task functions*/
void task1_diffie_hellman(const big_int& q, const big_int& alpha)
{ using namespace std;
    /*pick private values, keeping it in the same range*/
    big_int x_alice = 2 + random_below(q - 3);
    big_int x_bob = 2 + random_below(q - 3);

    big_int y_alice = mod_pow(alpha, x_alice, q);
    big_int y_bob = mod_pow(alpha, x_bob, q);

    /*public value exchange - A & B*/
    big_int s_alice = mod_pow(y_bob, x_alice, q);
    big_int s_bob = mod_pow(y_alice, x_bob, q);
    /*s_alice and s_bob must be identical mathematically*/

    vector<uchar> key_alice = sha256_key(s_alice);
    vector<uchar> key_bob = sha256_key(s_bob);
    vector<uchar> iv0 = random_bytes(NUM_KEY_BYTES);
    vector<uchar> iv1 = random_bytes(NUM_KEY_BYTES);

    string m0 = "bob test";
    string m1 = "alice test";

    vector<uchar> c0 = cbc_encrypt({m0.begin(), m0.end()}, key_alice, iv0);
    vector<uchar> c1 = cbc_encrypt({m1.begin(), m1.end()}, key_bob, iv1);

    cout << "Bob's shared secret: " << s_bob << "\n";
    cout << "Alice's shared secret: " << s_alice << "\n";
    cout << "Prev. 2 shared secrets should have the same value.\n";

    cout << "Alice's ciphertext: "; print_hex(c0);
    vector<uchar> bob_received = cbc_decrypt(c0, key_bob, iv0);
    cout << "Bob reads: " << string(bob_received.begin(), bob_received.end()) << '\n';

    cout << "Bob's ciphertext: "; print_hex(c1);
    vector<uchar> alice_received = cbc_decrypt(c1, key_alice, iv1);
    cout << "Alice reads: " << string(alice_received.begin(), alice_received.end()) << '\n';
}

void task2_mitm(const big_int& q, const big_int& alpha)
{ using namespace std;
    big_int x_alice = 2 + random_below(q - 3);
    big_int x_bob = 2 + random_below(q - 3);

    big_int y_alice = mod_pow(alpha, x_alice, q);
    big_int y_bob = mod_pow(alpha, x_bob, q);
    (void)y_alice; (void)y_bob;
    big_int alice_received = q, bob_received = q;
    big_int s_alice = mod_pow(alice_received, x_alice, q);
    big_int s_bob = mod_pow(bob_received, x_bob, q);

    string m0 = "bob test";
    string m1 = "alice test";

    vector<uchar> iv0 = random_bytes(NUM_KEY_BYTES);
    vector<uchar> iv1 = random_bytes(NUM_KEY_BYTES);
    vector<uchar> c0 = cbc_encrypt({m0.begin(), m0.end()}, sha256_key(s_alice), iv0);
    vector<uchar> c1 = cbc_encrypt({m1.begin(), m1.end()}, sha256_key(s_bob), iv1);
    vector<uchar> p0 = cbc_decrypt(c0, sha256_key(0), iv0);
    vector<uchar> p1 = cbc_decrypt(c1, sha256_key(0), iv1);

    cout << "Public keys replaced with q (s = 0): " << string(p0.begin(), p0.end())
         << " / " << string(p1.begin(), p1.end()) << '\n';

    /*mallory attack substituting the generator*/
    for (big_int modified_alpha : vector<big_int>{1, q, q - 1}) {
        y_alice = mod_pow(modified_alpha, x_alice, q);
        y_bob = mod_pow(modified_alpha, x_bob, q);
        s_alice = mod_pow(y_bob, x_alice, q);
        s_bob = mod_pow(y_alice, x_bob, q);

        /*given alpha = q - 1, the parity is visible in exchanged public values*/
        big_int mallory_s = modified_alpha == 1 ? big_int(1)
            : modified_alpha == q ? big_int(0)
            : (y_alice == q - 1 && y_bob == q - 1 ? q - 1 : big_int(1));

        iv0 = random_bytes(NUM_KEY_BYTES);
        iv1 = random_bytes(NUM_KEY_BYTES);
        c0 = cbc_encrypt({m0.begin(), m0.end()}, sha256_key(s_alice), iv0);
        c1 = cbc_encrypt({m1.begin(), m1.end()}, sha256_key(s_bob), iv1);
        p0 = cbc_decrypt(c0, sha256_key(mallory_s), iv0);
        p1 = cbc_decrypt(c1, sha256_key(mallory_s), iv1);
        cout << "Generator " << modified_alpha << " (s = " << mallory_s << "): "
             << string(p0.begin(), p0.end()) << " / " << string(p1.begin(), p1.end()) << '\n';
    }
}

void task3_rsa(size_t size)
{ using namespace std;
    /*test w 1024 bits*/
    rsa_keys alice = generate_rsa(size);
    string text = "alice test";
    big_int message = from_bytes({text.begin(), text.end()});
    big_int c = rsa_encrypt(message, alice);
    big_int m = rsa_decrypt(c, alice);
    vector<uchar> decoded = to_bytes(m);
    cout << "RSA round trip: " << string(decoded.begin(), decoded.end()) << '\n';

    /*test w 2048 bits*/
    
    big_int bob_secret;
    do {
        bob_secret = 2 + random_below(alice.n - 3);
    } while (gcd_int(bob_secret, alice.n) != 1);
    big_int bob_c = rsa_encrypt(bob_secret, alice);

    cout << "Exchange matches: " << rsa_decrypt(bob_c, alice) << " and " << bob_secret << "\n";

    /*mallory substitutes with encryption of known secret 2*/
    big_int modified_c = mod_pow(2, alice.e, alice.n);
    big_int alice_secret = rsa_decrypt(modified_c, alice);
    vector<uchar> iv = random_bytes(NUM_KEY_BYTES);
    string reply = "alice test";
    vector<uchar> c0 = cbc_encrypt({reply.begin(), reply.end()}, sha256_key(alice_secret), iv);
    vector<uchar> recovered = cbc_decrypt(c0, sha256_key(2), iv);
    cout << "RSA MITM: " << string(recovered.begin(), recovered.end()) << '\n';

    /*forged signature due to multiplicative property*/
    big_int m1 = 3, m2 = 5;
    big_int sig1 = mod_pow(m1, alice.d, alice.n);
    big_int sig2 = mod_pow(m2, alice.d, alice.n);
    big_int m3 = (m1 * m2) % alice.n;
    big_int sig3 = (sig1 * sig2) % alice.n;
    cout << "Forged signature is still valid, following two values equal: " << mod_pow(sig3, alice.e, alice.n) << " and " << m3 << "\n";
}

int main()
{ using namespace std;
    /*task 1 demo*/
    cout << "Small Diffie-Hellman example\n";
    task1_diffie_hellman(37, 5);
    cout << "Large Diffie-Hellman example\n";
    big_int q("0x"
            "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
            "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
            "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
            "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
            "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
            "DF1FB2BC2E4A4371");
    big_int alpha("0x"
        "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
        "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
        "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
        "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
        "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
        "855E6EEB22B3B2E5");
    task1_diffie_hellman(q, alpha);
    /*task 2 demo*/
    cout << "MITM example\n";
    task2_mitm(37, 5);
    /*task 3 demo*/
    cout << "RSA example\n";
    task3_rsa(RSA_BITS);
    cout << "testing RSA max prime\n";
    task3_rsa(RSA_BITS*2);
}