#include <iostream>
#include <memory>

#include "../db/database.h"
#include "../utils/Menu.hpp"
#include "../utils/Keys.hpp"
#include "../utils/Certificates.hpp"
#include "../utils/CRL.hpp"
#include "../utils/UserFileParser.hpp"


int main() {
    unique_ptr<Menu> menu = make_unique<Menu>();

    menu.get()->adminMainMenu();

    int choice = -1;

        while (choice != 0) {
        cin >> choice;

        switch(choice) {
        case 1:
            menu.get()->createRootKey();
            break;
        case 2:
            menu.get()->createIssuerKey();
            break;
        case 3:
            menu.get()->createRootCertificate();
            break;
        case 4:
            menu.get()->createIssuerCertificate();
            break;
        case 5:
            menu.get()->signUserReq();
            break;
        case 7:
            menu.get()->suspendUserCert();
            break;
        case 8:
            menu.get()->revokeUserCert();
            break;
        case 9:
            menu.get()->deleteIssuerCert();
            break;
        case 10:
            menu.get()->deleteCertReq();
            break;
        case 11:
            menu.get()->displayCRLs();
            break;
        case 12:
            menu.get()->displayRootCerts();
            break;
        case 13:
            menu.get()->displayIssuerCerts();
            break;
        case 14:
            menu.get()->displayCSRs();
            break;
        case 0:
            exit(0);
        default:
            cout << "Некорректный ввод. Попробуйте снова.\n";
            break;
        }

        menu.get()->adminMainMenu();
    }
}