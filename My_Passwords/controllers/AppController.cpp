#include "AppController.h"
#include "../managers/DatabaseManager.h"
#include "../managers/SessionManager.h"
#include "../managers/PasswordManager.h"
#include <iostream>

using namespace std;

void AppController::run() {
    DatabaseManager db;
    if (!db.connect("passwords.db")) {
        cout << "DB connection failed." << endl;
        return;
    }

    SessionManager session;
    PasswordManager password;

    while (true) {
        cout << "1. Login\n2. Register\n0. Exit\nSelect: ";
        int choice;
        cin >> choice;

        if (choice == 1) {
            if (session.loginUser(db.getDB())) {
                cout << "User: " << session.getUsername() << " logged in.\n";
            }
        }
        else if (choice == 2) {
            session.registerUser(db.getDB());
        }
        else if (choice == 0) {
            break;
        }
        else {
            cout << "Invalid choice.\n";
        }

        while (session.isLoggedIn()) {
            system("cls");
            choice = 0;
            cout << "1. Add Password\n2. Display Password\n3. Search Password\n4. Edit Password\nSelect: ";
            cin >> choice;

            switch (choice) {
            case 1:
                password.insertPassword(db.getDB(), session);
                system("pause");
            }
        }
    }
}
