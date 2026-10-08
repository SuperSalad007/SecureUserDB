#include "secure_user_db.h"

#include <iostream>
#include <string>
#include <conio.h>
#include <windows.h>
#include <cctype>
#include <cstring>

// ============================================================
// Утилиты ввода
// ============================================================
std::string ReadLine(const std::string& prompt) {
    std::cout << prompt;
    std::string s;
    std::getline(std::cin, s);
    return s;
}

std::string ReadPassword(const std::string& prompt) {
    std::cout << prompt;
    std::string pwd;
    int ch;
    while ((ch = _getch()) != '\r') {
        if (ch == '\b') {
            if (!pwd.empty()) {
                pwd.pop_back();
                std::cout << "\b \b";
            }
        }
        else if (ch >= 32 && ch < 127) {
            pwd.push_back((char)ch);
            std::cout << '*';
        }
    }
    std::cout << '\n';
    return pwd;
}

int ReadInt(const std::string& prompt) {
    while (true) {
        std::string s = ReadLine(prompt);
        try { return std::stoi(s); }
        catch (...) { std::cout << "Введите целое число.\n"; }
    }
}

// ============================================================
// Проверка ограничения (вариант 5 ЛР1: цифры + знаки препинания)
// ============================================================
bool ValidatePasswordRestriction(const std::string& pwd, std::string& err) {
    bool hasDigit = false, hasPunct = false;
    for (unsigned char c : pwd) {
        if (isdigit(c)) hasDigit = true;
        if (ispunct(c)) hasPunct = true;
    }
    if (!hasDigit) { err = "Пароль должен содержать цифру."; return false; }
    if (!hasPunct) { err = "Пароль должен содержать знак препинания."; return false; }
    return true;
}

// ============================================================
// Смена пароля с проверкой старого (для меню администратора/пользователя)
// ============================================================
void DoChangePassword(SecureUserDB& db, const std::string& username) {
    std::cout << "\n=== Смена пароля ===\n";
    std::string oldPwd = ReadPassword("Старый пароль: ");

    if (!db.ValidatePassword(username, oldPwd)) {
        std::cout << "Неверный старый пароль!\n";
        return;
    }

    while (true) {
        std::string p1 = ReadPassword("Новый пароль: ");
        std::string p2 = ReadPassword("Подтверждение: ");
        if (p1 != p2) { std::cout << "Пароли не совпадают.\n"; continue; }

        UserRecord u;
        db.FindUser(username, u);
        if (u.pwdRestricted) {
            std::string err;
            if (!ValidatePasswordRestriction(p1, err)) {
                std::cout << err << "\n"; continue;
            }
        }

        std::string err;
        if (db.ChangePassword(username, oldPwd, p1, true, err))
            std::cout << "Пароль успешно изменён.\n";
        else
            std::cout << "Ошибка: " << err << "\n";
        return;
    }
}

// ============================================================
// Принудительная смена пароля (ИЗМЕНЕНО ПОД ТРЕБОВАНИЯ)
// ============================================================
void ForceChangePassword(SecureUserDB& db, const std::string& username) {
    std::cout << "\n*** ТРЕБУЕТСЯ СМЕНА ПАРОЛЯ ***\n";
    std::cout << "Для подтверждения личности введите текущий (старый) пароль.\n";

    // Шаг 1: Обязательная проверка старого пароля
    std::string oldPwd = ReadPassword("Старый пароль: ");
    if (!db.ValidatePassword(username, oldPwd)) {
        std::cout << "Неверный старый пароль! Смена пароля отменена. Возврат к экрану входа.\n";
        return; // Возвращаемся в цикл Login, чтобы пользователь попробовал снова
    }

    // Шаг 2: Ввод нового пароля с учетом ограничений
    while (true) {
        std::string p1 = ReadPassword("Новый пароль: ");
        std::string p2 = ReadPassword("Подтверждение: ");
        if (p1 != p2) { std::cout << "Пароли не совпадают.\n"; continue; }

        UserRecord u;
        db.FindUser(username, u);
        if (u.pwdRestricted) {
            std::string err;
            if (!ValidatePasswordRestriction(p1, err)) {
                std::cout << err << "\n"; continue;
            }
        }

        std::string err;
        // Передаем oldPwd и true, чтобы база данных перепроверила старый пароль
        if (db.ChangePassword(username, oldPwd, p1, true, err)) {
            std::cout << "Пароль успешно изменён. Пожалуйста, войдите в систему заново с новым паролем.\n";
        }
        else {
            std::cout << "Ошибка: " << err << "\n";
        }
        return; // Возвращаемся в цикл Login
    }
}

// ============================================================
// Меню администратора
// ============================================================
void AdminMenu(SecureUserDB& db, const std::string& username) {
    while (true) {
        std::cout << "\n======== МЕНЮ АДМИНИСТРАТОРА ========\n"
            << "1. Сменить свой пароль\n"
            << "2. Список пользователей\n"
            << "3. Добавить пользователя\n"
            << "4. Блокировать/разблокировать\n"
            << "5. Изменить ограничения\n"
            << "6. Сменить пароль пользователя\n"
            << "0. Выход\n"
            << "Выбор: ";

        int c; std::cin >> c; std::cin.ignore(10000, '\n');

        switch (c) {
        case 1: DoChangePassword(db, username); break;

        case 2:
            std::cout << "\n--- Пользователи ---\n";
            for (auto& u : db.GetUsers()) {
                std::cout << "  " << u.username
                    << " | блок: " << (u.blocked ? "да" : "нет")
                    << " | огр: " << (u.pwdRestricted ? "да" : "нет")
                    << " | мин: " << u.minLength
                    << " | смена: " << (u.mustChangePassword ? "да" : "нет")
                    << "\n";
            }
            break;

        case 3: {
            std::string name = ReadLine("Имя: ");
            std::cout << (db.AddUser(name) ? "Добавлен.\n" : "Ошибка.\n");
            break;
        }
        case 4: {
            std::string name = ReadLine("Имя: ");
            if (!db.UserExists(name)) { std::cout << "Не найден.\n"; break; }
            std::cout << "1 - блок, 0 - разблок: ";
            int b; std::cin >> b; std::cin.ignore(10000, '\n');
            db.SetBlocked(name, b != 0);
            std::cout << "Готово.\n";
            break;
        }
        case 5: {
            std::string name = ReadLine("Имя: ");
            if (!db.UserExists(name)) { std::cout << "Не найден.\n"; break; }
            std::cout << "1 - вкл ограничения, 0 - откл: ";
            int r; std::cin >> r; std::cin.ignore(10000, '\n');
            int minLen = 4;
            if (r) minLen = ReadInt("Мин. длина: ");
            db.SetRestrictions(name, r != 0, minLen);
            std::cout << "Готово. Пользователь сменит пароль при след. входе.\n";
            break;
        }
        case 6: {
            std::string name = ReadLine("Имя: ");
            if (!db.UserExists(name)) { std::cout << "Не найден.\n"; break; }
            std::string p1 = ReadPassword("Новый пароль: ");
            std::string p2 = ReadPassword("Подтверждение: ");
            if (p1 != p2) { std::cout << "Не совпадают.\n"; break; }
            std::string err;
            if (db.ChangePassword(name, "", p1, false, err))
                std::cout << "Пароль изменён.\n";
            else
                std::cout << "Ошибка: " << err << "\n";
            break;
        }
        case 0: return;
        default: std::cout << "Неверный выбор.\n";
        }
    }
}

// ============================================================
// Меню обычного пользователя
// ============================================================
void UserMenu(SecureUserDB& db, const std::string& username) {
    while (true) {
        std::cout << "\n======== МЕНЮ ПОЛЬЗОВАТЕЛЯ ========\n"
            << "1. Сменить пароль\n"
            << "0. Выход\n"
            << "Выбор: ";

        int c; std::cin >> c; std::cin.ignore(10000, '\n');
        switch (c) {
        case 1: DoChangePassword(db, username); break;
        case 0: return;
        default: std::cout << "Неверный выбор.\n";
        }
    }
}

// ============================================================
// Вход в систему (ИЗМЕНЕНО ПОД ТРЕБОВАНИЯ)
// ============================================================
bool Login(SecureUserDB& db, std::string& outUsername, bool& outIsAdmin) {
    // Шаг 1: парольная фраза для расшифровки БД
    std::cout << "========= РАСШИФРОВКА БАЗЫ =========\n";
    std::string master = ReadPassword("Парольная фраза: ");
    if (master.empty()) {
        std::cout << "Отказ от ввода. Выход.\n";
        return false;
    }

    if (!db.Open("users.dat", master)) {
        std::cout << "Неверная парольная фраза или повреждённый файл.\n";
        return false;
    }
    std::cout << "База расшифрована.\n";

    // Шаг 2: вход в систему
    int attempts = 0;
    while (true) {
        std::cout << "\n========= ВХОД В СИСТЕМУ =========\n";
        std::string name = ReadLine("Имя пользователя: ");

        if (!db.UserExists(name)) {
            std::cout << "Пользователь не найден.\n";
            if (++attempts >= 3) { std::cout << "Превышен лимит попыток.\n"; return false; }
            continue;
        }
        if (db.IsBlocked(name)) {
            std::cout << "Учётная запись заблокирована!\n";
            return false;
        }

        std::string pwd = ReadPassword("Пароль: ");

        if (!db.ValidatePassword(name, pwd)) {
            std::cout << "Неверный пароль.\n";
            if (++attempts >= 3) { std::cout << "Превышен лимит попыток.\n"; return false; }
            continue;
        }

        // --- ЛОГИКА ПРИНУДИТЕЛЬНОЙ СМЕНЫ ПАРОЛЯ ---
        if (db.MustChangePassword(name)) {
            ForceChangePassword(db, name);
            // После вызова ForceChangePassword программа НЕ входит в систему.
            // Цикл while(true) продолжается, и пользователя снова просят ввести логин и пароль.
            // Это реализует требование "не должен сразу проваливаться в систему".
            continue;
        }

        // Если смена пароля не требуется — успешный вход
        outUsername = name;
        outIsAdmin = db.IsAdmin(name);
        return true;
    }
}

// ============================================================
// Точка входа
// ============================================================
int main() {
    SetConsoleCP(1251);
    SetConsoleOutputCP(1251);

    std::cout << "Лабораторная работа №3. Вариант 5.\n"
        << "RC2 / CFB / MD2 / salt.\n\n";

    SecureUserDB db;
    std::string username;
    bool isAdmin = false;

    if (!Login(db, username, isAdmin)) {
        std::cout << "\nЗавершение работы.\n";
        return 0;
    }

    std::cout << "\nДобро пожаловать, " << username << "!\n";

    if (isAdmin) AdminMenu(db, username);
    else         UserMenu(db, username);

    db.SaveAndClose();
    std::cout << "Данные сохранены.\n";
    return 0;
}