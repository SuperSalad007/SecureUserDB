#pragma once

#include <windows.h>
#include <wincrypt.h>

#include <string>
#include <vector>
#include <cstdint>

// Запись учётной записи (сериализуется как есть)
#pragma pack(push, 1)
struct UserRecord {
    char username[32];       // имя пользователя
    char password[64];       // пароль
    int  pwdLength;          // длина пароля
    bool blocked;            // блокировка учётной записи
    bool pwdRestricted;      // ограничения на пароль
    int  minLength;          // минимальная длина
    bool mustChangePassword; // принудительная смена при след. входе
};
#pragma pack(pop)

class SecureUserDB {
public:
    SecureUserDB();
    ~SecureUserDB();

    bool Open(const std::string& filename, const std::string& masterPassword);
    bool SaveAndClose();
    bool IsOpen() const { return isOpen_; }

    // Поиск и проверки
    bool UserExists(const std::string& username) const;
    bool FindUser(const std::string& username, UserRecord& out) const;
    bool ValidatePassword(const std::string& username,
        const std::string& password) const;
    bool IsBlocked(const std::string& username) const;
    bool IsAdmin(const std::string& username) const;
    bool MustChangePassword(const std::string& username) const;

    // Изменения
    bool AddUser(const std::string& username);
    bool SetBlocked(const std::string& username, bool blocked);
    bool SetRestrictions(const std::string& username,
        bool restricted, int minLength);
    bool ChangePassword(const std::string& username,
        const std::string& oldPwd,
        const std::string& newPwd,
        bool checkOld,
        std::string& errMsg);

    const std::vector<UserRecord>& GetUsers() const { return users_; }

private:
    bool InitCrypto();
    void CleanupCrypto();
    bool CreateSessionKey(const std::string& passphrase);
    bool EncryptBuffer(const std::vector<uint8_t>& plain,
        std::vector<uint8_t>& out);
    bool DecryptBuffer(const std::vector<uint8_t>& cipher,
        std::vector<uint8_t>& out);

    std::string filename_;
    std::vector<UserRecord> users_;
    bool isOpen_;

    HCRYPTPROV hProv_;
    HCRYPTKEY  hKey_;
    HCRYPTHASH hHash_;
};
