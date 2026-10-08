#include "secure_user_db.h"

#include <fstream>
#include <cstring>

// Автоматическая линковка библиотек CryptoAPI
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

// ============================================================
// Конструктор / деструктор
// ============================================================
SecureUserDB::SecureUserDB()
    : isOpen_(false), hProv_(0), hKey_(0), hHash_(0)
{
    InitCrypto();
}

SecureUserDB::~SecureUserDB() {
    SaveAndClose();
    CleanupCrypto();
}

// ============================================================
// Инициализация криптопровайдера
// Для варианта 5 нужен MD2 -> пробуем Base CSP
// ============================================================
bool SecureUserDB::InitCrypto() {
    // 1) Base CSP — поддерживает MD2 (вариант 5)
    if (CryptAcquireContextA(&hProv_, NULL,
        "Microsoft Base Cryptographic Provider v1.0",
        PROV_RSA_FULL, 0)) return true;

    // 2) Стандартный провайдер
    if (CryptAcquireContextA(&hProv_, NULL, NULL,
        PROV_RSA_FULL, 0)) return true;

    // 3) Регистрация нового ключевого набора
    if (CryptAcquireContextA(&hProv_, NULL,
        "Microsoft Base Cryptographic Provider v1.0",
        PROV_RSA_FULL, CRYPT_NEWKEYSET)) return true;
    if (CryptAcquireContextA(&hProv_, NULL, NULL,
        PROV_RSA_FULL, CRYPT_NEWKEYSET)) return true;

    return false;
}

void SecureUserDB::CleanupCrypto() {
    if (hKey_) { CryptDestroyKey(hKey_);         hKey_ = 0; }
    if (hHash_) { CryptDestroyHash(hHash_);       hHash_ = 0; }
    if (hProv_) { CryptReleaseContext(hProv_, 0); hProv_ = 0; }
}

// ============================================================
// Генерация сеансового ключа
// ВАРИАНТ 5: MD2 + RC2 + CFB + CRYPT_CREATE_SALT
// ============================================================
bool SecureUserDB::CreateSessionKey(const std::string& passphrase) {
    if (hKey_) { CryptDestroyKey(hKey_);   hKey_ = 0; }
    if (hHash_) { CryptDestroyHash(hHash_); hHash_ = 0; }

    // --- 1) MD2 ---
    ALG_ID hashAlg = CALG_MD2;
    if (!CryptCreateHash(hProv_, hashAlg, 0, 0, &hHash_)) {
        // Fallback на MD5, если MD2 недоступен
        hashAlg = CALG_MD5;
        if (!CryptCreateHash(hProv_, hashAlg, 0, 0, &hHash_))
            return false;
    }

    if (!CryptHashData(hHash_, (const BYTE*)passphrase.data(),
        (DWORD)passphrase.size(), 0))
        return false;

    // --- 2) RC2 (блочный шифр) ---
    ALG_ID cipherAlg = CALG_RC2;

    // --- 3) Добавление случайной примеси (salt) ---
    DWORD flags = CRYPT_EXPORTABLE | CRYPT_CREATE_SALT;

    if (!CryptDeriveKey(hProv_, cipherAlg, hHash_, flags, &hKey_))
        return false;

    // --- 4) Режим CFB (обратная связь по шифротексту) ---
    DWORD mode = CRYPT_MODE_CFB;
    if (!CryptSetKeyParam(hKey_, KP_MODE, (BYTE*)&mode, 0))
        return false;

    return true;
}

// ============================================================
// Шифрование буфера
// Формат: [DWORD saltLen][salt][encrypted data]
// ============================================================
bool SecureUserDB::EncryptBuffer(const std::vector<uint8_t>& plain,
    std::vector<uint8_t>& out)
{
    if (!hKey_) return false;

    // Читаем соль из ключа
    DWORD saltLen = 0;
    CryptGetKeyParam(hKey_, KP_SALT, NULL, &saltLen, 0);
    std::vector<uint8_t> salt(saltLen);
    if (saltLen > 0) {
        if (!CryptGetKeyParam(hKey_, KP_SALT, salt.data(), &saltLen, 0)) {
            saltLen = 0;
            salt.clear();
        }
    }

    DWORD bufLen = (DWORD)plain.size() + 16;
    std::vector<uint8_t> buf(bufLen);
    if (!plain.empty()) memcpy(buf.data(), plain.data(), plain.size());
    DWORD dataLen = (DWORD)plain.size();

    if (!CryptEncrypt(hKey_, 0, TRUE, 0, buf.data(), &dataLen, bufLen))
        return false;

    out.clear();
    out.resize(sizeof(DWORD) + saltLen + dataLen);
    uint8_t* p = out.data();
    memcpy(p, &saltLen, sizeof(DWORD)); p += sizeof(DWORD);
    if (saltLen) { memcpy(p, salt.data(), saltLen); p += saltLen; }
    memcpy(p, buf.data(), dataLen);
    return true;
}

// ============================================================
// Расшифрование буфера
// ============================================================
bool SecureUserDB::DecryptBuffer(const std::vector<uint8_t>& cipher,
    std::vector<uint8_t>& out)
{
    if (!hKey_) return false;
    if (cipher.size() < sizeof(DWORD)) return false;

    const uint8_t* p = cipher.data();

    DWORD saltLen = 0;
    memcpy(&saltLen, p, sizeof(DWORD));
    p += sizeof(DWORD);

    if (cipher.size() < sizeof(DWORD) + saltLen) return false;

    if (saltLen > 0) {
        if (!CryptSetKeyParam(hKey_, KP_SALT, p, 0)) return false;
        p += saltLen;
    }

    DWORD encLen = (DWORD)(cipher.size() - sizeof(DWORD) - saltLen);
    std::vector<uint8_t> buf(encLen);
    memcpy(buf.data(), p, encLen);

    DWORD decLen = encLen;
    if (!CryptDecrypt(hKey_, 0, TRUE, 0, buf.data(), &decLen))
        return false;

    out.assign(buf.begin(), buf.begin() + decLen);
    return true;
}

// ============================================================
// Открытие БД
// ============================================================
bool SecureUserDB::Open(const std::string& filename,
    const std::string& masterPassword)
{
    filename_ = filename;

    if (!CreateSessionKey(masterPassword)) return false;

    std::ifstream fin(filename, std::ios::binary);

    // Файла нет — создаём с ADMIN/admin
    if (!fin) {
        users_.clear();
        UserRecord admin;
        memset(&admin, 0, sizeof(admin));
        strcpy_s(admin.username, "ADMIN");
        strcpy_s(admin.password, "admin");
        admin.pwdLength = 5;
        admin.blocked = false;
        admin.pwdRestricted = true;
        admin.minLength = 6;
        admin.mustChangePassword = true;
        users_.push_back(admin);
        isOpen_ = true;
        SaveAndClose();
        return Open(filename, masterPassword);
    }

    fin.seekg(0, std::ios::end);
    std::streampos sz = fin.tellg();
    fin.seekg(0, std::ios::beg);
    std::vector<uint8_t> cipher((size_t)sz);
    if (sz > 0) fin.read((char*)cipher.data(), sz);
    fin.close();

    std::vector<uint8_t> plain;
    if (!DecryptBuffer(cipher, plain))
        return false;

    if (plain.size() % sizeof(UserRecord) != 0)
        return false;

    size_t n = plain.size() / sizeof(UserRecord);
    users_.resize(n);
    if (n > 0) memcpy(users_.data(), plain.data(), n * sizeof(UserRecord));

    // Проверка правильности парольной фразы
    // по наличию учётной записи ADMIN
    bool hasAdmin = false;
    for (auto& u : users_) {
        if (strcmp(u.username, "ADMIN") == 0) { hasAdmin = true; break; }
    }
    if (!hasAdmin) {
        users_.clear();
        return false;
    }

    isOpen_ = true;
    return true;
}

// ============================================================
// Сохранение (шифрование обратно, перезапись файла)
// ============================================================
bool SecureUserDB::SaveAndClose() {
    if (!isOpen_) return true;

    std::vector<uint8_t> plain(users_.size() * sizeof(UserRecord));
    if (!users_.empty()) memcpy(plain.data(), users_.data(), plain.size());

    std::vector<uint8_t> cipher;
    if (!EncryptBuffer(plain, cipher)) return false;

    std::ofstream fout(filename_, std::ios::binary | std::ios::trunc);
    if (!fout) return false;
    fout.write((const char*)cipher.data(), cipher.size());
    fout.close();

    isOpen_ = false;
    return true;
}

// ============================================================
// Поиск и проверки
// ============================================================
bool SecureUserDB::UserExists(const std::string& username) const {
    for (auto& u : users_) if (username == u.username) return true;
    return false;
}

bool SecureUserDB::FindUser(const std::string& username, UserRecord& out) const {
    for (auto& u : users_) if (username == u.username) { out = u; return true; }
    return false;
}

bool SecureUserDB::ValidatePassword(const std::string& username,
    const std::string& password) const
{
    UserRecord u;
    if (!FindUser(username, u)) return false;
    if (u.blocked) return false;
    return password == u.password;
}

bool SecureUserDB::IsBlocked(const std::string& username) const {
    UserRecord u;
    if (!FindUser(username, u)) return false;
    return u.blocked;
}

bool SecureUserDB::IsAdmin(const std::string& username) const {
    return username == "ADMIN";
}

bool SecureUserDB::MustChangePassword(const std::string& username) const {
    UserRecord u;
    if (!FindUser(username, u)) return false;
    return u.mustChangePassword;
}

// ============================================================
// Изменения
// ============================================================
bool SecureUserDB::AddUser(const std::string& username) {
    if (UserExists(username)) return false;
    if (username.size() >= 32) return false;
    UserRecord u;
    memset(&u, 0, sizeof(u));
    strncpy_s(u.username, username.c_str(), 31);
    u.password[0] = '\0';
    u.pwdLength = 0;
    u.blocked = false;
    u.pwdRestricted = false;
    u.minLength = 4;
    u.mustChangePassword = true;
    users_.push_back(u);
    return true;
}

bool SecureUserDB::SetBlocked(const std::string& username, bool blocked) {
    for (auto& u : users_) {
        if (username == u.username) { u.blocked = blocked; return true; }
    }
    return false;
}

bool SecureUserDB::SetRestrictions(const std::string& username,
    bool restricted, int minLength)
{
    for (auto& u : users_) {
        if (username == u.username) {
            u.pwdRestricted = restricted;
            u.minLength = minLength;
            u.mustChangePassword = true;   // принудительная смена
            return true;
        }
    }
    return false;
}

bool SecureUserDB::ChangePassword(const std::string& username,
    const std::string& oldPwd,
    const std::string& newPwd,
    bool checkOld,
    std::string& errMsg)
{
    for (auto& u : users_) {
        if (username != u.username) continue;

        if (checkOld && strcmp(u.password, oldPwd.c_str()) != 0) {
            errMsg = "Неверный старый пароль!";
            return false;
        }

        if (u.pwdRestricted && (int)newPwd.size() < u.minLength) {
            errMsg = "Пароль слишком короткий. Минимум: " +
                std::to_string(u.minLength);
            return false;
        }

        if (newPwd.size() >= sizeof(u.password)) {
            errMsg = "Пароль слишком длинный";
            return false;
        }

        strncpy_s(u.password, newPwd.c_str(), sizeof(u.password) - 1);
        u.pwdLength = (int)newPwd.size();
        u.mustChangePassword = false;
        return true;
    }
    errMsg = "Пользователь не найден";
    return false;
}