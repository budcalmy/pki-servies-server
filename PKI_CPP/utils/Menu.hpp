#pragma once

#include <iostream>
#include <filesystem>
#include <string>
#include <memory>

#include "../paths.hpp"
#include "./CRL.hpp"
#include "./Certificates.hpp"
#include "./Keys.hpp"
#include "./UserFileParser.hpp"


namespace fs = std::filesystem;

class Menu {
private:
    unique_ptr<Database> db;
    unique_ptr<Keys> keys;
    unique_ptr<Certificates> certificates;
    static void displayDirectoryContents(const std::string& dir);
    int deleteFileFromPath(const std::string& pathToFile, const std::string& filename);

public:

    Menu() {
        db = std::make_unique<Database>(DB_PATH, "1234");
        keys = std::make_unique<Keys>();
        certificates = std::make_unique<Certificates>();
    }

    static void adminMainMenu();
    static void registratorMainMenu();

    //display methods
    static void displayCRLs();
    static void displayCSRs();
    static void displayRootKeys();
    static void displayIssuerKeys();
    static void displayRootKeyInfo();
    static void displayIssuerKeyInfo();
    static void displayCurrentCSRInfo();
    static void displayRootCerts();
    static void displayIssuerCerts();

    //create methods
    void createRootKey();
    void createIssuerKey();
    void createRootCertificate();
    void createIssuerCertificate();
    void createCertReq();

    void signUserReq();
    void suspendUserCert();
    void revokeUserCert();

    //delete methods
    void deleteIssuerCert();
    void deleteCertReq();

};

inline void Menu::adminMainMenu()
{
    std::cout << "\nМеню управления PKI (admin):\n\n";
    std::cout << "1. Создать корневой ключ\n";
    std::cout << "2. Создать эмитентский ключ\n";
    std::cout << "3. Создать корневой шаблон\n";
    std::cout << "4. Создать эмитентский сертификат (dev in progress..)\n";
    std::cout << "5. Создать пользовательский запрос на сертификат (dev in progress..)\n\n";

    std::cout << "6. Подписать пользовательский запрос на сертификат\n\n";
    std::cout << "7. Приостановить действие пользовательского сертификата\n\n";
    std::cout << "8. Отозвать пользовательский сертификат\n\n";

    std::cout << "9. Удалить эмитентский сертификат\n";
    std::cout << "10. Удалить пользовательский запрос на сертификат\n\n";

    std::cout << "11. Просмотреть список отозванных сертификатов\n";
    std::cout << "12. Просмотреть список корневый шаблонов\n";
    std::cout << "13. Просмотреть список эмитенских сертификатов\n";
    std::cout << "14. Просмотреть список пользовательских запросов\n\n";

    std::cout << "0. Выход\n";
    std::cout << "Введите номер действия: ";
}

inline void Menu::registratorMainMenu()
{
    std::cout << "\nМеню управления PKI (registrator):\n\n";
    std::cout << "1. Создать пользовательский запрос на сертификат\n\n";

    std::cout << "2. Удалить пользовательский запрос на сертификат\n\n";

    std::cout << "3. Просмотреть список пользовательских запросов\n\n";

    std::cout << "4. Просмотреть конкретный пользовательский запрос\n\n";

    std::cout << "0. Выход\n";
    std::cout << "Введите номер действия: ";
}

void Menu::displayDirectoryContents(const std::string &dir)
{

    if (!fs::exists(dir)) {
        std::cerr << "Путь не существует: " << dir << std::endl;
        return;
    }

    if (!fs::is_directory(dir)) {
        std::cerr << "Указанный путь не является директорией: " << dir << std::endl;
        return;
    }

    int index = 1;
    for (const auto& entry : fs::directory_iterator(dir)) {
        if (fs::is_regular_file(entry.status())) {
            std::cout << index << ". " << entry.path().filename().string()
                        << " | " << entry.path() << std::endl;
            index++;
        }
    }
}


inline int Menu::deleteFileFromPath(const std::string &pathToFile, const std::string &filename)
{
    try {
        filesystem::path filepath = filesystem::path(pathToFile) / filename;

        if (!filesystem::exists(filepath)) {
            std::cerr << "Файл " + filepath.string() + " не существует.\n";
            return 0;
        }

        filesystem::remove(filepath);
        std::cout << "Файл " << filepath.string() << " успешно удалён.\n";
        return 1;
    } catch (const std::exception& ex) {
        std::cerr << "Ошибка при удалении файла: " + std::string(ex.what());
        return 0;
    }
}

inline void Menu::displayCRLs()
{
    std::cout << "Просмотр списка отозванных сертификатов:\n";
    CRL::displayCRLlist(ADMIN_ISSUER_CRL_FILE);
}

inline void Menu::displayCSRs()
{
    std::cout << "Просмотр запросов пользователей на выдачу сертификата:\n";
    displayDirectoryContents(ISSUER_CSR_PATH);
}

inline void Menu::displayRootKeys()
{
    std::cout << "Просмотр списка ключей корневого центра сертификации:\n";
    displayDirectoryContents(ROOT_KEYS);
}

inline void Menu::displayIssuerKeys()
{
    std::cout << "Просмотр списка ключей эмитентского центра сертификации:\n";
    displayDirectoryContents(ISSUER_KEYS);
}

inline void Menu::displayRootKeyInfo()
{
}

inline void Menu::displayIssuerKeyInfo()
{
}

inline void Menu::displayCurrentCSRInfo()
{
    std::cout << "Введите название файла запроса на сертификат (прим. req1.csr.pem):\n";
    string filename = ""; std::cin >> filename;
    filename = '/' + filename;

    string filepath = ISSUER_CSR_PATH + filename;

    try {
        Certificates::displayCertificateReq(filepath);
    } catch (std::runtime_error) {
        std::cerr << "Файл с именем " + filename + " не найден.";
    }
}

inline void Menu::displayRootCerts()
{
    std::cout << "Просмотр шаблонов корневого центра сертификации:\n";
    displayDirectoryContents(ROOT_CERTS_PATH);
}

inline void Menu::displayIssuerCerts()
{
    std::cout << "Просмотр шаблонов эмитентского центра сертификации:\n";
    displayDirectoryContents(ISSUER_CERTS_PATH);
}

inline void Menu::createRootKey()
{
    std::string newRootPkeyName = "";

    std::string oldRootKeyName = keys.get()->getRootPkeyName();

    filesystem::path rootPkeyPath = filesystem::path(std::string(ROOT_PRIVATE_KEY_PATH)) / oldRootKeyName;
    
    if (filesystem::exists(rootPkeyPath)) {
        std::cout << "Корневой приватный ключ уже существует.\n";
        displayDirectoryContents(ROOT_PRIVATE_KEY_PATH);
        std::cout << "Выберите действие:\n";
        std::cout << "1. Просмотреть существующий ключ.\n";
        std::cout << "2. Создать новый ключ.\n";
        std::cout << "0. Назад в главное меню.\n";

        int choice = -1;

        do {
            
            std::cin.ignore();
            std::cin >> choice;

            switch (choice) {
                case 1:
                    keys.get()->displayKey(rootPkeyPath);
                    break;
                case 2:
                    std::cout << "Введите новое имя приватного ключа (прим. root.key.pem):\n";
                    std::cin.ignore();
                    getline(std::cin, newRootPkeyName);
                    try {
                        if (deleteFileFromPath(ROOT_PRIVATE_KEY_PATH, keys.get()->getRootPkeyName()) == 1) // пытаемся удалить старый ключ
                        {
                            keys.get()->generateKey(ROOT_PRIVATE_KEY_PATH, newRootPkeyName); // создание нового (newKeyName).key.pem
                        }
                        else {
                            std::cerr << "Ошибка при попытке удалить старый приватный ключ.\n";
                            break;
                        }
                    } catch (std::runtime_error) {
                        std::cerr << "Ошибка во время создания нового приватного ключа.\n";
                        break;
                    }

                    keys.get()->setRootPkeyName(newRootPkeyName); // изменение поля объекта класса keys
                    std::cout << "Новый ключ с именем " + newRootPkeyName + " успешно создан.";
                    break;
                case 0:
                    break;
                default:
                    std::cout << "Некорректный ввод. Попробуйте снова.\n";
                    break;
            }
        } while (choice == -1);
    }
}

inline void Menu::createIssuerKey()
{
    std::string newIssuerPkeyName = "";

    std::string oldIssuerKeyName = keys.get()->getIssuerPkeyName();

    filesystem::path issuerPkeyPath = filesystem::path(std::string(ISSUER_PRIVATE_KEY_PATH)) / oldIssuerKeyName;
    
    if (filesystem::exists(issuerPkeyPath)) {
        std::cout << "Корневой приватный ключ уже существует.\n";
        displayDirectoryContents(ISSUER_PRIVATE_KEY_PATH);
        std::cout << "Выберите действие:\n";
        std::cout << "1. Просмотреть существующий ключ.\n";
        std::cout << "2. Создать новый ключ.\n";
        std::cout << "0. Назад в главное меню.\n";

        int choice = -1;

        do {
            
            std::cin.ignore();
            std::cin >> choice;

            switch (choice) {
                case 1:
                    keys.get()->displayKey(issuerPkeyPath);
                    break;
                case 2:
                    std::cout << "Введите новое имя приватного ключа (прим. issuer.key.pem):\n";
                    std::cin.ignore();
                    getline(std::cin, newIssuerPkeyName);
                    try {
                        if (deleteFileFromPath(ROOT_PRIVATE_KEY_PATH, keys.get()->getIssuerPkeyName()) == 1) // пытаемся удалить старый ключ
                        {
                            keys.get()->generateKey(ROOT_PRIVATE_KEY_PATH, newIssuerPkeyName); // создание нового (newKeyName).key.pem
                        }
                        else {
                            std::cerr << "Ошибка при попытке удалить старый приватный ключ.\n";
                            break;
                        }
                    } catch (std::runtime_error) {
                        std::cerr << "Ошибка во время создания нового приватного ключа.\n";
                        break;
                    }

                    keys.get()->setRootPkeyName(newIssuerPkeyName); // изменение поля объекта класса keys
                    std::cout << "Новый ключ с именем " + newIssuerPkeyName + " успешно создан.";
                    break;
                case 0:
                    break;
                default:
                    std::cout << "Некорректный ввод. Попробуйте снова.\n";
                    break;
            }
        } while (choice == -1);
    }
}

inline void Menu::createRootCertificate()
{
}

inline void Menu::createIssuerCertificate()
{
}

void Menu::createCertReq()
{
    EVP_PKEY* pkey = nullptr;
    try {
        pkey = keys.get()->readExistingKeyFromPath(filesystem::path(ROOT_PRIVATE_KEY_PATH) / keys.get()->getRootPkeyName());
    } catch (std::runtime_error) {
        std::cerr << "Неудалось прочитать приватный ключ корневого центра сертификации.\n";
        return;
    }

    this->displayDirectoryContents(USER_REQS_PATH);
    std::cout << "Выберите файл пользовательских данных для создания запроса (укажите название файла):\n";
    string filename = "";
    cin.ignore();
    getline(std::cin, filename);

    filesystem::path filepath = filesystem::path(USER_REQS_PATH) / filename;

    if (!filesystem::exists(filepath)) {
        std::cerr << "ОШИБКА: Файла с именем " + filename + " не существует.\n";
        return;
    }

    UserInfo userInfo = parseUserInfo(filepath);

    std::cout << "Проверьте соответвие полученных данных:\ncountryName – " << userInfo.countryName << "\norganizationName – " << userInfo.organizationName << "\ncommonName(fio) – " << userInfo.fio << std::endl;
    std::cout << "Создать запрос по этим данным? y/n\n";
    string ans = "";
    getline(std::cin, ans);

    if (ans == "y") {
        string filenameWithoutEx = filesystem::path(filename).stem().string();
        certificates.get()->genereteIssuerCSR(*db, pkey, filenameWithoutEx, userInfo.countryName, userInfo.organizationName, userInfo.fio);
        return;
    } 
    else {
        std::cout << "Создание запроса было прервано.\n";
        return;
    }

}

inline void Menu::signUserReq()
{
    EVP_PKEY* pkey = nullptr;
    X509* rootCert = nullptr;
    X509_REQ* req = nullptr;
    X509* userCert = nullptr;

    try {
        pkey = keys.get()->readExistingKeyFromPath(filesystem::path(ROOT_PRIVATE_KEY_PATH) / keys.get()->getRootPkeyName());
    } catch (std::runtime_error) {
        std::cerr << "Неудалось прочитать приватный ключ КУЦ.\n";
    }

    try {
        rootCert = certificates.get()->readExistingX509FromPath(filesystem::path(ROOT_CERTS_PATH) / ADMIN_CERT_NAME);
    } catch (std::runtime_error) {
        std::cerr << "Неудалось прочитать самоподписанный сертификат КУЦ.\n";
    }


    try {
        this->displayDirectoryContents(ISSUER_CSR_PATH);
        std::cout << "Выберите запрос, который необходимо подписать (укажите название файла без расширения):\n";
        string reqFilename = "";
        std::cin.ignore();
        getline(std::cin, reqFilename);

        filesystem::path filepath = filesystem::path(ISSUER_CSR_PATH) / (reqFilename + ".csr.pem");

        if (!filesystem::exists(filepath)) {
            std::cerr << "ОШИБКА: Файла с именем " + reqFilename + " не существует.\n";
            throw runtime_error("");
        }
        else {
            req = certificates.get()->readExistingX509_ReqFromPath(filepath);
        }

        userCert = certificates.get()->signIssuerReqCSR(reqFilename + ".cert.pem", req, rootCert, pkey, *db);

        // EVP_PKEY* tempKeyForCryptocontainer = keys.get()->generateKey(TEMP_PATH, "temp.key.pem");
        
        filesystem::path userinfoFilepath = filesystem::path(USER_REQS_PATH) / (reqFilename + ".txt");
        string userPassword = parseUserInfo(userinfoFilepath).password;

        // certificates.get()->generatePKCS12(userCert, tempKeyForCryptocontainer, userPassword, reqFilename);
        certificates.get()->generatePKCS12(userCert, pkey, userPassword, reqFilename);

        // deleteFileFromPath(TEMP_PATH, "temp.key.pem");

    } catch (std::runtime_error) {
        std::cerr << "Неудалось подписать пользовательский запрос на сертификат.\n";
    }

}

inline void Menu::suspendUserCert()
{
    
}

inline void Menu::revokeUserCert()
{
}

inline void Menu::deleteIssuerCert()
{
}

void Menu::deleteCertReq()
{
    std::cout << "Укажите название файла запроса на сертификат, который нужно удалить:\n";
    string reqFileName = "";
    std::cin.ignore();
    getline(std::cin, reqFileName);

    try {
        if (deleteFileFromPath(ISSUER_CSR_PATH, reqFileName) == 1) //пытаемся удалить файл из директории запросов
        { 
            if (db.get()->deleteFromReqTable(reqFileName) == 1) //пытаемся удалить запись в таблице запросов
            {
                std::cout << "Успешное удаление запроса " + reqFileName;
            }
        }
    } catch (std::runtime_error) {
        std::cerr << "Возникла ошибка при удалении запроса " + reqFileName;
    }
}
