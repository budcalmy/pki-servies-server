cmake_minimum_required(VERSION 3.16)
project(PKI_servies)

set(CMAKE_CXX_STANDARD 20)

# Собираем superadmin
add_executable(superadmin ../executables/superadmin.cpp ../db/database.cpp)

# Собираем admin
add_executable(admin ../executables/admin.cpp ../db/database.cpp)

# Собираем registrar
add_executable(registrar ../executables/registrator.cpp ../db/database.cpp)

# Ищем зависимости
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)

# Связываем библиотеки
target_link_libraries(superadmin OpenSSL::SSL OpenSSL::Crypto SQLite::SQLite3)
target_link_libraries(admin OpenSSL::SSL OpenSSL::Crypto SQLite::SQLite3)
target_link_libraries(registrar OpenSSL::SSL OpenSSL::Crypto SQLite::SQLite3)

# Добавляем определения
target_compile_definitions(superadmin PRIVATE SQLITE_HAS_CODEC)
target_compile_definitions(admin PRIVATE SQLITE_HAS_CODEC)
target_compile_definitions(registrar PRIVATE SQLITE_HAS_CODEC)