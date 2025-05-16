#include "DatabaseManager.h"
#include <iostream>

using namespace std;

bool DatabaseManager::connect(const std::string& db_name) {
    int result = sqlite3_open(db_name.c_str(), &db);

    if (result != SQLITE_OK) {
        cerr << "Failed to open database: " << sqlite3_errmsg(db) << endl;
        return false;
    }

    cout << "Database opened successfully!" << endl;

    const char* create_users_table =
        "CREATE TABLE IF NOT EXISTS users ("
        "username TEXT PRIMARY KEY,"
        "password_hash TEXT NOT NULL);";

    const char* create_passwords_table =
        "CREATE TABLE IF NOT EXISTS passwords ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "username TEXT NOT NULL,"
        "site TEXT NOT NULL,"
        "site_id TEXT,"
        "site_pw TEXT,"
        "description TEXT,"
        "FOREIGN KEY(username) REFERENCES users(username));";

    char* errMsg = nullptr;

    if (sqlite3_exec(db, create_users_table, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        cerr << "Failed to create users table: " << errMsg << endl;
        return false;
    }

    if (sqlite3_exec(db, create_passwords_table, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        cerr << "Failed to create passwords table: " << errMsg << endl;
        return false;
    }

    cout << "Tables created/loaded successfully!" << endl;

    return true;
}

sqlite3* DatabaseManager::getDB() const {
    return db;
}
