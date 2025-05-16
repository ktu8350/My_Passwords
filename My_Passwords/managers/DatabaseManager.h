#ifndef DATABASE_MANAGER_H
#define DATABASE_MANAGER_H

#include "../external/sqlite/sqlite3.h"
#include <string>

class DatabaseManager {
private:
    sqlite3* db = nullptr;

public:
    bool connect(const std::string& db_name);  // DB 열기 및 테이블 생성
    sqlite3* getDB() const;

};

#endif
