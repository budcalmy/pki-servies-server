#include <iostream>
#include <memory>
#include <filesystem>

#include "../db/database.h"
#include "../utils/Menu.hpp"
#include "../utils/Keys.hpp"
#include "../utils/Certificates.hpp"
#include "../utils/CRL.hpp"

using namespace std;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " --key-length <key length> ..." << endl;
        return 1;
    }

    int key_length;
    string root_key_name;
    string issuer_key_name;
    string root_cert_name;
    string db_name;
    string db_password;
    string crl_name;

    // Парсинг аргументов
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--key-length" && i + 1 < argc) {
            key_length = std::stoi(argv[++i]);
        } else if (arg == "--root-key" && i + 1 < argc) {
            root_key_name = argv[++i];
        } else if (arg == "--issuer-key" && i + 1 < argc) {
            issuer_key_name = argv[++i];
        } else if (arg == "--root-cert" && i + 1 < argc) {
            root_cert_name = argv[++i];
        } else if (arg == "--db-password" && i + 1 < argc) {
            db_password = argv[++i];
        } else if (arg == "--crl-name" && i + 1 < argc) {
            crl_name = argv[++i];
        }
    }


    //for logging
    cout << "Key length: " << key_length << endl;
    cout << "Root key name: " << root_key_name << endl;
    cout << "Issuer key name: " << issuer_key_name << endl;
    cout << "Root certificate name: " << root_cert_name << endl;
    cout << "Database password: " << db_password << endl;
    cout << "CRL name: " << crl_name << endl;

    //инициализация бд
    unique_ptr<Database> db = make_unique<Database>(DB_PATH, db_password);

    unique_ptr<Keys> keys = make_unique<Keys>();
    unique_ptr<Certificates> certs = make_unique<Certificates>();

    // //генерация приватных ключей для КУЦ и УЦ
    EVP_PKEY* pkey = keys.get()->generateKey(ROOT_PRIVATE_KEY_PATH, root_key_name);
    keys.get()->generateKey(ISSUER_PRIVATE_KEY_PATH, issuer_key_name);

    // //генерация самоподписанного сертификата
    X509* root_cert = certs.get()->generateCertificate(*db, pkey, ROOT_CERTS_PATH, root_cert_name);

    // //инициализация crl файла и структуры
    unique_ptr<CRL> crl = make_unique<CRL>((filesystem::path(CRL_PATH) / crl_name).string(), pkey, root_cert);

    return 0;
}