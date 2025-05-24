#ifndef PASSWORD_MANAGER_H
#define PASSWORD_MANAGER_H

#include <string>
#include <vector>
#include "../external/sqlite/sqlite3.h"
#include "SessionManager.h"

class PasswordManager {
public:
    struct Password {
        int id;
        std::string username;
        std::string site;
        std::string site_id;
        std::string site_pw;
        std::string description;
    };
    struct PasswordInput {
        std::string site;
        std::string site_id;
        std::string site_pw;
        std::string site_pw_check;
        std::string description;
    };


    bool insertPassword(sqlite3* db, SessionManager& session);
    bool isDuplicate(sqlite3* db, SessionManager& session, const std::string& site, const std::string& site_id);
    bool loadPassword(sqlite3* db, SessionManager& session);
    void displayPassword();
    void searchPassword();
private:
    std::vector<Password> passwords;
};

#endif
