#include "SessionManager.h"
#include <iostream>
#include "../external/sha256_string.h"

using namespace std;

void SessionManager::login(const std::string& user) {
    username = user;
    is_logged_in = true;
}

void SessionManager::logout() {
    username.clear();
    is_logged_in = false;
}

bool SessionManager::isLoggedIn() const {
    return is_logged_in;
}

std::string SessionManager::getUsername() const {
    return username;
}

bool SessionManager::loginUser(sqlite3* db) {
	system("cls");
	string username;
	string password;
	cout << "Username: ";
	cin >> username;

	cout << "Password: ";
	cin >> password;

	string password_hash = sha256(password);
	const char* verify_user =
		"SELECT username FROM users WHERE username = ? AND password_hash = ?;";
	sqlite3_stmt* user_stmt;

	sqlite3_prepare_v2(db, verify_user, -1, &user_stmt, nullptr);
	sqlite3_bind_text(user_stmt, 1, username.c_str(), -1, SQLITE_STATIC);
	sqlite3_bind_text(user_stmt, 2, password_hash.c_str(), -1, SQLITE_STATIC);

	if (sqlite3_step(user_stmt) != SQLITE_ROW) {
		cout << "Incorrect username or/and password" << endl;
		sqlite3_finalize(user_stmt);
		return 0;
	}
	sqlite3_finalize(user_stmt);
	cout << "Login successfully" << endl;
	system("pause");
	this->login(username);
	return 1;
}

bool SessionManager::registerUser(sqlite3* db) {
	system("cls");
	string username;

	cout << "Please enter a username: " << endl;
	cin >> username;
	sqlite3_stmt* check_stmt;
	sqlite3_stmt* insert_stmt;

	const char* check_username = "SELECT * From users WHERE username = ?;";
	const char* insert_username = "INSERT INTO users (username, password_hash) VALUES(?, ?);";

	sqlite3_prepare_v2(db, check_username, -1, &check_stmt, nullptr);
	sqlite3_bind_text(check_stmt, 1, username.c_str(), -1, SQLITE_STATIC);

	if (sqlite3_step(check_stmt) == SQLITE_ROW) {
		cout << "Username already exists." << endl;
		sqlite3_finalize(check_stmt);
		return 0;
	}
	sqlite3_finalize(check_stmt);

	string password;
	cout << "Please enter a password" << endl;
	cin >> password;

	string password_hash = sha256(password);

	sqlite3_prepare_v2(db, insert_username, -1, &insert_stmt, nullptr);
	sqlite3_bind_text(insert_stmt, 1, username.c_str(), -1, SQLITE_STATIC);
	sqlite3_bind_text(insert_stmt, 2, password_hash.c_str(), -1, SQLITE_STATIC);

	if (sqlite3_step(insert_stmt) != SQLITE_DONE) {
		cout << "Failed to create user: " << sqlite3_errmsg(db) << endl;
		sqlite3_finalize(insert_stmt);
		return 0;
	}

	sqlite3_finalize(insert_stmt);
	cout << "User created successfully!" << endl;
	this->login(username);
	return 1;
}