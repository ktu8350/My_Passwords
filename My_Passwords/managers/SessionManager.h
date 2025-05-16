#ifndef SESSION_MANAGER_H
#define SESSION_MANAGER_H

#include <string>
#include <vector>
#include "../external/sqlite/sqlite3.h"

class SessionManager {
private:
	bool is_logged_in = false;
	std::string username;

public:
	void login(const std::string& user);
	void logout();
	bool isLoggedIn() const;
	std::string getUsername() const;
	
	bool loginUser(sqlite3* db);
	bool registerUser(sqlite3* db);
};

#endif // !SESSION_MANAGER_H
