#pragma once

#define ADMIN_ROOT_PRIVATE_KEY_NAME "root.key.pem"
#define ADMIN_ISSUER_PRIVATE_KEY_NAME "issuer.key.pem"
#define ADMIN_CERT_NAME "root.cert.pem"
#define ADMIN_ISSUER_CRL_FILE "../CA/issuing-ca/crl/issuer_crl.pem"
#define ADMIN_ROOT_CRL_FILE "../CA/root-ca/crl/root_crl.pem"


#define ROOT_CRL "./PKI_CPP/CA/root-ca/crl"
#define ISSUER_CRL "./PKI_CPP/CA/issuing-ca/crl"
#define USER_REQS_PATH "./PKI_CPP/CA/user_reqs_data"
#define TEMP_PATH "./PKI_CPP/CA/temp"
#define DB_PATH "./PKI_CPP/db/root.db"
#define DB_SCHEMA "./PKI_CPP/db/schema.sql"
#define ROOT_PRIVATE_KEY_PATH "./PKI_CPP/CA/root-ca/private"
#define ROOT_CNF "./PKI_CPP/CA/config/root_openssl.cnf"
#define ROOT_CERTS_PATH "./PKI_CPP/CA/root-ca/certs"
#define ISSUER_PRIVATE_KEY_PATH "./PKI_CPP/CA/issuing-ca/private"
#define ISSUER_CNF "./PKI_CPP/CA/config/issuing_openssl.cnf"
#define ISSUER_CSR_PATH "./PKI_CPP/CA/issuing-ca/csr"
#define ISSUER_CERTS_PATH "./PKI_CPP/CA/issuing-ca/certs"
#define PKCS12_PATH "./PKI_CPP/CA/pkcs12"
#define CRL_PATH "./PKI_CPP/CA/issuing-ca/crl"