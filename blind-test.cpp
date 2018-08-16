#include "cryptlib.h"
#include "integer.h"
#include "nbtheory.h"
#include "osrng.h"
#include "rsa.h"
#include "sha.h"
using namespace CryptoPP;

#include <iostream>
#include <stdexcept>
using std::cout;
using std::endl;
using std::runtime_error;

#include <sys/time.h>
double get_time(void)
//some code taken from Victor Shoup's NTL library
{
    static struct timeval last_tv, tv;
    static int first = 1;
    static double res = 0;

    if (first) {
	gettimeofday(&last_tv, NULL);
	first = 0;
	return 0;
    } else {
	gettimeofday(&tv, NULL);
	res += tv.tv_sec - last_tv.tv_sec;
	res += (tv.tv_usec - last_tv.tv_usec) / 1000000.0;
	last_tv = tv;

	return res;
    }
}

int main(int argc, char* argv[])
{
    // Bob artificially small key pair
    AutoSeededRandomPool prng;
    RSA::PrivateKey privKey;

    privKey.GenerateRandomWithKeySize(prng, 256);
    RSA::PublicKey pubKey(privKey);

    // Convenience
    const Integer& n = pubKey.GetModulus();
    const Integer& e = pubKey.GetPublicExponent();
    const Integer& d = privKey.GetPrivateExponent();

    // Print params
    //cout << "Pub mod: " << std::hex << pubKey.GetModulus() << endl;
    //cout << "Pub exp: " << std::hex << e << endl;
    //cout << "Priv mod: " << std::hex << privKey.GetModulus() << endl;
    //cout << "Priv exp: " << std::hex << d << endl;

    // Alice original message to be signed by Bob
    SecByteBlock orig((const byte*)"secret", 6);
	byte digest[SHA256::DIGESTSIZE];
    SHA256 hash;
	hash.CalculateDigest(digest, orig, orig.size());
    Integer msg(digest, SHA256::DIGESTSIZE);
    cout << "Message: " << std::hex << msg << endl;

    // Alice blinding
    Integer r;
    do {
        r.Randomize(prng, Integer::One(), n - Integer::One());
    } while (!RelativelyPrime(r, n));

    // Blinding factor
    Integer b = a_exp_b_mod_c(r, e, n);
    cout << "Blind factor: " << std::hex << b << endl;

    // Alice blinded message
    Integer blindedMsg = a_times_b_mod_c(msg, b, n);
    cout << "Blinded msg: " << std::hex << blindedMsg << endl;

    // Bob sign
    Integer ss = privKey.CalculateInverse(prng, blindedMsg);
    cout << "Blind sign: " << ss << endl;

    // Alice checks s(s'(x)) = x. This is from Chaum's paper
    Integer verifyBlindedMsg = pubKey.ApplyFunction(ss);	// ss^e mode n
    cout << "Verified blinded msg: " << verifyBlindedMsg << endl;
    if (verifyBlindedMsg != blindedMsg)
        throw runtime_error("Alice cross-check failed");

    // Alice remove blinding
    Integer s = a_times_b_mod_c(ss, r.InverseMod(n), n);
    cout << "Unblind sign: " << s << endl;
    Integer origSign = privKey.CalculateInverse(prng, msg);
    cout << "Original sign: " << origSign << endl;
    if (s != origSign)
        throw runtime_error("Alice cross-check failed");

    // Eve verifies
    Integer verifyMsg = pubKey.ApplyFunction(s);	// s^e mode n
    cout << "Verified msg: " << std::hex << verifyMsg << endl;
    if (verifyMsg != msg)
        throw runtime_error("Alice cross-check failed");

    cout << "Verified signature" << endl;

    return 0;
}
