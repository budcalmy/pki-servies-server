#pragma once

#include <iostream>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <stdexcept>
#include <filesystem>

// Структура для хранения информации о пользователе
struct UserInfo {
    std::string fio;
    std::string countryName;
    std::string organizationName;
    std::string password;
};

// Функция для парсинга данных из файла
UserInfo parseUserInfo(const std::string& filePath) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        throw std::runtime_error("Не удалось открыть файл для чтения: " + filePath);
    }

    std::unordered_map<std::string, std::string> fields;
    std::string line;
    
    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string key, value;

        if (std::getline(iss, key, ':') && std::getline(iss, value)) {
            key.erase(key.find_last_not_of(" \n\r\t") + 1);
            value.erase(0, value.find_first_not_of(" \n\r\t"));
            fields[key] = value;
        }
    }

    file.close();

    if (fields.find("fio") == fields.end() ||
        fields.find("countryName") == fields.end() ||
        fields.find("organizationName") == fields.end() ||
        fields.find("password") == fields.end()) {
        throw std::runtime_error("Не все необходимые поля присутствуют в файле.");
    }

    UserInfo userInfo;
    userInfo.fio = fields["fio"];
    userInfo.countryName = fields["countryName"];
    userInfo.organizationName = fields["organizationName"];
    userInfo.password = fields["password"];

    return userInfo;
}

