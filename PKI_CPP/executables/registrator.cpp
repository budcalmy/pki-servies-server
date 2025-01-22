#include <iostream>

#include "../db/database.h"
#include "../utils/Menu.hpp"
#include "../utils/Keys.hpp"
#include "../utils/Certificates.hpp"
#include "../utils/CRL.hpp"
#include "../utils/UserFileParser.hpp"

using namespace std;


int main() {
    Menu menu;

    int choice = -1;

    menu.registratorMainMenu();

    while (choice != 0) {
        cin >> choice;

        switch(choice) {
        case 1:
            menu.createCertReq();
            break;
        case 2:
            menu.deleteCertReq();
            break;
        case 3:
            menu.displayCSRs();
            break;
        case 4:
            menu.displayCurrentCSRInfo();
            break;
        case 0:
            exit(0);
        default:
            cout << "Некорректный ввод. Попробуйте снова.\n";
            break;
        }
        menu.registratorMainMenu();
    }
}