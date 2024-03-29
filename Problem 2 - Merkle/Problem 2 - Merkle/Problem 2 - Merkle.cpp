#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <Windows.h>
#include <wincrypt.h>

using namespace std;

void encrypt(const string& inputFileName, const string& outputFileName, int rounds) {
    // Open input file
    ifstream inputFile(inputFileName, ios::binary | ios::in);
    if (!inputFile) {
        cerr << "Error: Could not open input file " << inputFileName << endl;
        return;
    }

    // Read key and plaintext from input file
    int key, plaintext;
    inputFile.read(reinterpret_cast<char*>(&key), sizeof(key));
    inputFile.read(reinterpret_cast<char*>(&plaintext), sizeof(plaintext));
    inputFile.close();

    // Initialize DES provider and key
    HCRYPTPROV hProv;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        cerr << "Error: CryptAcquireContext failed" << endl;
        return;
    }

    if (!CryptSetKeyParam(hProv, 0, CRYPT_IMPL_PROVIDER, 0, 0)) {
        cerr << "Error: CryptSetKeyParam failed" << endl;
        CryptReleaseContext(hProv, 0);
        return;
    }

    HCRYPTKEY hKey;
    if (!CryptCreateSymmetricKey(hProv, &hKey)) {
        cerr << "Error: CryptCreateSymmetricKey failed" << endl;
        CryptReleaseContext(hProv, 0);
        return;
    }

    if (!CryptSetKeyParam(hKey, 0, CRYPT_KEYSIZE, reinterpret_cast<BYTE*>(&key), 0)) {
        cerr << "Error: CryptSetKeyParam failed" << endl;
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return;
    }

    // Initialize encryption context
    HCRYPTKEY hEncryptKey;
    if (!CryptGetUserKey(hProv, &hEncryptKey)) {
        cerr << "Error: CryptGetUserKey failed" << endl;
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return;
    }

    if (!CryptSetKeyParam(hEncryptKey, 0, CRYPT_MODE, CRYPT_MODE_ECB, 0)) {
        cerr << "Error: CryptSetKeyParam failed" << endl;
        CryptDestroyKey(hEncryptKey);
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return;
    }

    // Encrypt plaintext with DES
    vector<BYTE> ciphertext(8);
    DWORD ciphertextLength = 8;
    for (int i = 0; i < rounds - 1; i++) {
        if (!CryptEncrypt(hEncryptKey, reinterpret_cast<BYTE*>(&plaintext), sizeof(plaintext), 0, NULL, &ciphertextLength, 0)) {
            cerr << "Error: CryptEncrypt failed" << endl;
            CryptDestroyKey(hEncryptKey);
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            return;
        }
        memcpy(&plaintext, ciphertext.data(), ciphertextLength);
    }

    // Apply IP-1
    BYTE ip1[8];
    ip1[0] = ciphertext[32];
    ip1[1] = ciphertext[1];
    ip1[2] = ciphertext[2];
    ip1[3] = ciphertext[3];
    ip1[4] = ciphertext[0];
    ip1[5] = ciphertext[33];
    ip1[6] = ciphertext[34];
    ip1[7] = ciphertext[35];

    // Write ciphertext to output file
    ofstream outputFile(outputFileName, ios::binary | ios::out);
    if (!outputFile) {
        cerr << "Error: Could not open output file " << outputFileName << endl;
        CryptDestroyKey(hEncryptKey);
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return;
    }
    outputFile.write(reinterpret_cast<char*>(ip1), 8);
    outputFile.close();

    // Clean up
    CryptDestroyKey(hEncryptKey);
    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);
}

int main(int argc, char* argv[]) {
    // Read input file
    ifstream inputFile("input.txt", ios::binary | ios::in);
    if (!inputFile) {
        cerr << "Error: Could not open input file" << endl;
        return 1;
    }

    // Read number of rounds, key, and plaintext from input file
    int rounds;
    inputFile.read(reinterpret_cast<char*>(&rounds), sizeof(rounds));
    BYTE key[8];
    inputFile.read(reinterpret_cast<char*>(key), 8);
    BYTE plaintext[8];
    inputFile.read(reinterpret_cast<char*>(plaintext), 8);
    inputFile.close();

    // Encrypt plaintext with DES
    encrypt("class_input_2A.txt", "Merkle_output_2A.txt", rounds);
    encrypt("class_input_2B.txt", "Merkle_output_2B.txt", rounds);
    encrypt("class_input_2C.txt", "Merkle_output_2C.txt", rounds);

    return 0;
}