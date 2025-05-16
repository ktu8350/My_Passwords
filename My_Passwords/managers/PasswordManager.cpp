#include "PasswordManager.h"
#include <iostream>
#include "../managers/CryptoManager.h"
#include "../external/sha256_string.h"

using namespace std;

bool PasswordManager::insertPassword(sqlite3* db, SessionManager& session) {
    system("cls");

    PasswordInput input;

    cout << "Please enter the service name (e.g, Gmail, Netflix, Google etc): " << endl;
    cin >> input.site;

    cout << "Please enter the username for the service: " << endl;
    cin >> input.site_id;

    if (isDuplicate(db, session, input.site, input.site_id)) {
        cout << "Duplicate Service name and username Found!" << endl;
        return 0;
    }

    cout << "Please enter the password" << endl;
    cin >> input.site_pw;

    cout << "Please enter the password again" << endl;
    cin >> input.site_pw_check;

    std::string encrypted_pw;
    std::string username_hash;

    if (input.site_pw == input.site_pw_check) {
        username_hash = sha256(session.getUsername());
        encrypted_pw = CryptoManager::xorEncrypt(input.site_pw, username_hash);
    }
    else {
        cout << "The password does not match!" << endl;
        system("pause");
        return 0;
    }

    cout << "Add description(optional)" << endl;
    cin >> input.description;

    const char* insert_sql =
        "INSERT INTO passwords (username, site, site_id, site_pw, description) "
        "VALUES (?, ?, ?, ?, ?);";

    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, insert_sql, -1, &stmt, nullptr);

    sqlite3_bind_text(stmt, 1, session.getUsername().c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, input.site.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, input.site_id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, encrypted_pw.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, input.description.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        cout << "Failed to insert password: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt);
        system("pause");
        return 0;
    }

    sqlite3_finalize(stmt);
    cout << "Password saved successfully!" << endl;
    system("pause");
    return 1;
}

bool PasswordManager::isDuplicate(sqlite3* db, SessionManager& session, const std::string& site, const std::string& site_id) {
    const char* sql = "SELECT 1 FROM passwords WHERE username = ? AND site = ? AND site_id = ?;";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    sqlite3_bind_text(stmt, 1, session.getUsername().c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, site.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, site_id.c_str(), -1, SQLITE_STATIC);

    bool exists = (sqlite3_step(stmt) == SQLITE_ROW);

    sqlite3_finalize(stmt);
    return exists;
}
