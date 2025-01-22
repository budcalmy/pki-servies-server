#pragma once

#include <iostream>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <variant>
#include <filesystem>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#define ROOT_KEYS "/root-ca/private"
#define ISSUER_KEYS "/issuing-ca/private"
#define DEFAULT_ROOT_PRIVATE_KEY_NAME "root.key.pem"
#define DEFAULT_ISSUER_PRIVATE_KEY_NAME "issuer.key.pem"
#define SUPERADMIN_KEY_SIZE 4096

using namespace std;

class Keys {
private:
    string rootPkeyName;
    string issuerPkeyName;
public:
    Keys() {
        // проверяем есть ли уже какой нибудь приватный ключ ROOT
        if (!(std::filesystem::directory_iterator(ROOT_PRIVATE_KEY_PATH) == std::filesystem::directory_iterator())) 
        {
            for (const auto& entry : std::filesystem::directory_iterator(ROOT_PRIVATE_KEY_PATH)) {
                if (entry.is_regular_file()) { 
                    rootPkeyName = entry.path().filename().string();
                }
            }
        }

        // проверяем есть ли уже какой нибудь приватный ключ ISSUER
        if (!(std::filesystem::directory_iterator(ISSUER_PRIVATE_KEY_PATH) == std::filesystem::directory_iterator()))
        {
            for (const auto& entry : std::filesystem::directory_iterator(ISSUER_PRIVATE_KEY_PATH)) { // читаем директорию
                if (entry.is_regular_file()) { 
                    issuerPkeyName = entry.path().filename().string(); // добываем имя файла приватного ключа и записываем его в поле
                }
            }
        }
    }

    string& getRootPkeyName() { return this->rootPkeyName; }
    string& getIssuerPkeyName() { return this->issuerPkeyName; }

    void setRootPkeyName(const string& newKeyName) { this->rootPkeyName = newKeyName; }
    void setIssuerPkeyName(const string& newKeyName) { this->issuerPkeyName = newKeyName; }

    EVP_PKEY* readExistingKeyFromPath(const string& keyPath);
    EVP_PKEY* generateKey(const string& keyOutPath, string keyFullOutPath);

    static void displayKey(const string& key);
};

EVP_PKEY* Keys::readExistingKeyFromPath(const string& keyPath) {
    unique_ptr<BIO, decltype(&BIO_free_all)> keyBio(BIO_new_file(keyPath.c_str(), "r"), BIO_free_all);
    if (!keyBio) {
        throw runtime_error("readExistingKeyFromPath: Ошибка при открытии файла с существующим ключом.");
    }

    EVP_PKEY* existingKey = PEM_read_bio_PrivateKey(keyBio.get(), nullptr, nullptr, nullptr);
    if (!existingKey) {
        throw runtime_error("readExistingKeyFromPath: Ошибка при чтении существующего ключа из файла.");
    }

    return existingKey;
}


EVP_PKEY* Keys::generateKey(const string& keyOutPath, string keyName) {
    filesystem::path keyPath;

    keyPath = filesystem::path(keyOutPath) / keyName;


    if (filesystem::exists(keyPath)) {
        cout << "generateKey: Приватный ключ уже существует: " << keyPath << "\n";
        EVP_PKEY* pkey = readExistingKeyFromPath(keyPath);
        return pkey;
    }

    // Создаем структуру для ключа
    unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(EVP_PKEY_new(), EVP_PKEY_free);
    unique_ptr<RSA, decltype(&RSA_free)> rsa(RSA_new(), RSA_free);
    unique_ptr<BIGNUM, decltype(&BN_free)> e(BN_new(), BN_free);

    if (!pkey || !rsa || !e) {
        throw runtime_error("generateKey: Ошибка при создании структуры для ключа");
    }

    // Устанавливаем экспоненту
    if (BN_set_word(e.get(), RSA_F4) != 1) {
        throw runtime_error("generateKey: Ошибка при установке значения экспоненты");
    }

    // Генерируем ключ
    if (RSA_generate_key_ex(rsa.get(), SUPERADMIN_KEY_SIZE, e.get(), nullptr) != 1) {
        throw runtime_error("generateKey: Ошибка при генерации ключа RSA");
    }

    // Привязываем RSA к EVP_PKEY
    if (EVP_PKEY_assign_RSA(pkey.get(), rsa.release()) != 1) {
        throw runtime_error("generateKey: Ошибка при привязке RSA к EVP_PKEY");
    }

    // Сохраняем ключ в файл
    unique_ptr<BIO, decltype(&BIO_free_all)> keyBio(BIO_new_file(keyPath.c_str(), "w"), BIO_free_all);
    if (!keyBio || PEM_write_bio_PrivateKey(keyBio.get(), pkey.get(), nullptr, nullptr, 0, nullptr, nullptr) == 0) {
        cerr << "generateKey: Ошибка при записи закрытого ключа в файл\n";
    }

    cout << "generateKey: Ключ успешно создан и сохранён по пути: " << keyPath << endl;

    // Возвращаем владение ключом вызывающей стороне
    return pkey.release();
}


void Keys::displayKey(const string& keyPath) {
    string command = "openssl pkey -in " + keyPath + " -text -noout";
    int result = system(command.c_str());
}

