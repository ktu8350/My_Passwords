#include "PasswordManager.h"
#include <iostream>
#include "../managers/CryptoManager.h"
#include "../external/sha256_string.h"

using namespace std;

bool PasswordManager::insertPassword(sqlite3* db, SessionManager& session) {
    system("cls");

    PasswordInput input;

    cout << "Please enter the service name (e.g, Gmail, Netflix, Google etc): " << endl;
    getline(cin >> ws, input.site);

    cout << "Please enter the username for the service: " << endl;
    getline(cin >> ws, input.site_id);

    if (isDuplicate(db, session, input.site, input.site_id)) {
        cout << "Duplicate Service name and username Found!" << endl;
        return 0;
    }

    cout << "Please enter the password" << endl;
    getline(cin >> ws, input.site_pw);

    cout << "Please enter the password again" << endl;
    getline(cin >> ws, input.site_pw_check);

    std::string encrypted_pw;
    std::string username_hash;

    if (input.site_pw == input.site_pw_check) {
        username_hash = sha256(session.getUsername());
        string raw_encrypted = CryptoManager::xorEncrypt(input.site_pw, username_hash);
        encrypted_pw = CryptoManager::base64Encode(raw_encrypted);
    }
    else {
        cout << "The password does not match!" << endl;
        system("pause");
        return 0;
    }

    cout << "Add description(optional)" << endl;
    getline(cin >> ws, input.description);

    const char* insert_sql =
        "INSERT INTO passwords (username, site, site_id, site_pw, description) "
        "VALUES (?, ?, ?, ?, ?);";

    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, insert_sql, -1, &stmt, nullptr);

    sqlite3_bind_text(stmt, 1, session.getUsername().c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, input.site.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, input.site_id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, encrypted_pw.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, input.description.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        cout << "Failed to insert password: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt);
        system("pause");
        return 0;
    }

    sqlite3_finalize(stmt);
    cout << "Password saved successfully!" << endl;
    loadPassword(db, session);
    system("pause");
    return 1;
}

bool PasswordManager::isDuplicate(sqlite3* db, SessionManager& session, const std::string& site, const std::string& site_id) {
    const char* sql = "SELECT 1 FROM passwords WHERE username = ? AND site = ? AND site_id = ?;";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << endl;
        return false;
    }

    sqlite3_bind_text(stmt, 1, session.getUsername().c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, site.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, site_id.c_str(), -1, SQLITE_STATIC);

    bool exists = (sqlite3_step(stmt) == SQLITE_ROW);

    sqlite3_finalize(stmt);
    return exists;
}

bool PasswordManager::loadPassword(sqlite3* db, SessionManager& session) {
    passwords.clear();
    const char* sql = "SELECT * FROM passwords WHERE username = ?;";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        cerr << "Failed to prepare  statement: " << sqlite3_errmsg(db) << endl;
        return false;
    }

    sqlite3_bind_text(stmt, 1, session.getUsername().c_str(), -1, SQLITE_STATIC);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Password p;
        p.id = sqlite3_column_int(stmt, 0);
        p.username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        p.site = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        p.site_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        string encrypted_base64 = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        string decoded = CryptoManager::base64Decode(encrypted_base64);
        string decrypted = CryptoManager::xorDecrypt(decoded, sha256(session.getUsername()));
        p.site_pw = decrypted;
        p.description = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));

        passwords.push_back(p);
    }

    sqlite3_finalize(stmt);
    return true;
}

void PasswordManager::displayPassword() {
    for (const auto& p : passwords) {
        cout << "ID: " << p.id << endl;
        cout << "Site: " << p.site << endl;
        cout << "Site ID: " << p.site_id << endl;
        cout << "Site Password: " << p.site_pw << endl;
        cout << "Description: " << p.description << endl;
        cout << "---------------------------" << endl;
    }

    system("pause");
    system("cls");
}

void PasswordManager::searchPassword() {
    string keyword;
    bool found = false;
    system("cls");
    cout << "Please enter a keyword to search\nEnter: ";
    getline(cin >> ws, keyword);
    cout << "Input" << keyword;
    for (const auto& p : passwords) {
        if (p.site.find(keyword) != string::npos ||
            p.site_id.find(keyword) != string::npos ||
            p.description.find(keyword) != string::npos) {
            cout << "ID: " << p.id << endl;
            cout << "Site: " << p.site << endl;
            cout << "Site ID: " << p.site_id << endl;
            cout << "Site Password: " << p.site_pw << endl;
            cout << "Description: " << p.description << endl;
            cout << "---------------------------" << endl;
            found = true;
        }
    }

    if (found == false) {
        cout << "No matching result found!" << endl;
    }

    system("pause");
    system("cls");
}

void PasswordManager::editPassword(sqlite3* db, SessionManager& session) {
    string site_search;
    string site_id_search;
    PasswordInput input;

    cout << "Please enter site name to search\nEnter: ";
    getline(cin >> ws, site_search);

    cout << "Please enter Account name to search\nEnter: ";
    getline(cin >> ws, site_id_search);

    for (auto it = passwords.begin(); it != passwords.end(); ++it) {
        if (it->site.find(site_search) != string::npos &&
            it->site_id.find(site_id_search) != string::npos) {

            cout << "\nResult found:\n";
            cout << "Site Name: " << it->site << endl;
            cout << "Account Name: " << it->site_id << endl;
            cout << "Password: " << it->site_pw << endl;
            cout << "Description: " << it->description << endl;
            cout << "-----------------------------------" << endl;

            cout << "Enter the new site name\nEnter: ";
            getline(cin >> ws, input.site);

            cout << "\nEnter the new Account Name\nEnter: ";
            getline(cin >> ws, input.site_id);

            if (isDuplicate(db, session, input.site, input.site_id)) {
                cout << "Duplicate Service name and username Found!" << endl;
                return;
            }

            cout << "\nEnter the new Password\nEnter: ";
            getline(cin >> ws, input.site_pw);

            cout << "\nPlease enter the password again\nEnter: ";
            getline(cin >> ws, input.site_pw_check);

            if (input.site_pw != input.site_pw_check) {
                cout << "Password does not match!" << endl;
                system("pause");
                return;
            }

            cout << "\nPlease enter description\nEnter: ";
            getline(cin >> ws, input.description);

            // Encrypt the password
            std::string username_hash = sha256(session.getUsername());
            std::string raw_encrypted = CryptoManager::xorEncrypt(input.site_pw, username_hash);
            std::string encrypted_pw = CryptoManager::base64Encode(raw_encrypted);

            // Update vector
            it->site = input.site;
            it->site_id = input.site_id;
            it->site_pw = input.site_pw;
            it->description = input.description;

            // Prepare SQL statement
            const char* sql = "UPDATE passwords SET site = ?, site_id = ?, site_pw = ?, description = ? WHERE id = ?;";
            sqlite3_stmt* stmt;

            if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
                cerr << "Failed to prepare update statement: " << sqlite3_errmsg(db) << endl;
                return;
            }

            sqlite3_bind_text(stmt, 1, input.site.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, input.site_id.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 3, encrypted_pw.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 4, input.description.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_int(stmt, 5, it->id);

            if (sqlite3_step(stmt) != SQLITE_DONE) {
                cerr << "Failed to update password: " << sqlite3_errmsg(db) << endl;
            }
            else {
                cout << "\nPassword updated successfully!" << endl;
            }

            sqlite3_finalize(stmt);
            system("pause");
            return;
        }
    }

    cout << "No matching result found!" << endl;
    system("pause");
}
