#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <iomanip>
#include "NebulaFox.h"
#include "skCrypter.h"

#define SK_W(str) ((const wchar_t*)skCrypt(str))
#define SK_A(str) ((const char*)skCrypt(str))

// 1. СТРУКТУРА CLOUD PAYLOAD (Data-Driven Security)
//
// Описывает секретные данные, которые НИКОГДА не хранятся внутри бинарника.
// Они зашифрованы на серверах NebulaFox и расшифровываются прямо в памяти
// только после успешной верификации лицензионного ключа и HWID устройства.
//
// #pragma pack(push, 1) запрещает компилятору добавлять выравнивающие байты.
// Без этой директивы sizeof(AppSecrets) в бинарнике не совпадет с размером
// HEX-строки на сервере, и GetCloudPayload() вернет ошибку несоответствия размера.

#pragma pack(push, 1)
struct AppSecrets {
    char apiKey[64];         // API-ключ стороннего сервиса (платежный шлюз, AI-сервис и т.д.)
    char backendUrl[96];     // Приватный URL вашего бэкенда, скрытый от анализа трафика
    char encryptionKey[32];  // AES мастер-ключ для расшифровки локальных данных приложения
    bool premiumUnlocked;    // Флаг: является ли данная лицензия премиум-тарифом
    uint32_t sessionTtl;     // Максимальная длительность сессии в секундах (зависит от тарифа)
};
#pragma pack(pop)

// 2. ГЕНЕРАТОР HEX-СТРОКИ ДЛЯ ДАШБОРДА
// Читает переменную или структуру из памяти и выводит готовую HEX-строку.
// Используйте один раз во время разработки, чтобы получить значение для вставки в дашборд.

static void PrintHexForDashboard(const void* data, size_t size, const char* label) {
    const BYTE* bytes = static_cast<const BYTE*>(data);
    std::cout << SK_A("[DEV] HEX для ") << label << SK_A(" (") << size << SK_A(" байт): ");
    for (size_t i = 0; i < size; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)bytes[i];
    }
    std::cout << std::dec << std::endl;
}

// Затирает содержимое строки нулями перед освобождением памяти
static void WipeString(std::string& s) {
    if (!s.empty()) SecureZeroMemory(s.data(), s.capacity());
    s.clear();
}

static void SafePause() {
    { auto s = std::string(SK_A("\nНажмите любую клавишу для выхода...")); std::cout << s << std::endl; WipeString(s); }
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    FlushConsoleInputBuffer(hIn);
    char buf[2] = {}; DWORD read = 0;
    ReadConsoleA(hIn, buf, 1, &read, NULL);
    SecureZeroMemory(buf, sizeof(buf));
}

// 3. ОСНОВНАЯ ЛОГИКА

int main() {
    SetConsoleTitleA(SK_A("FoxAuth"));

    // -------------------------------------------------------------------------
    // ГЕНЕРАТОР PAYLOAD (инструмент разработчика)
    //
    // Шаг 1: Заполните структуру AppSecrets реальными значениями.
    // Шаг 2: Запустите этот блок один раз и скопируйте HEX-строку из вывода.
    // Шаг 3: Вставьте HEX-строку в дашборд FoxAuth -> ваш проект -> Cloud Payload.
    // Шаг 4: Закомментируйте этот блок перед сборкой релизной версии.
    // -------------------------------------------------------------------------

    /* std::cout << "[DEV] Генератор Payload" << std::endl;

    // Вариант 1: HEX для полной структуры AppSecrets
    AppSecrets mySecrets = {};
    strncpy_s(mySecrets.apiKey,       "sk-live-abc123yourrealkey",         sizeof(mySecrets.apiKey)       - 1);
    strncpy_s(mySecrets.backendUrl,   "https://api.internal.yourapp.com",  sizeof(mySecrets.backendUrl)   - 1);
    strncpy_s(mySecrets.encryptionKey,"your-32-byte-aes-master-key!!!!",   sizeof(mySecrets.encryptionKey) - 1);
    mySecrets.premiumUnlocked = true;
    mySecrets.sessionTtl      = 3600;
    PrintHexForDashboard(&mySecrets, sizeof(mySecrets), "AppSecrets");
    // Скопируйте вывод и вставьте в дашборд FoxAuth -> Cloud Payload

    // Вариант 2: HEX для одиночного 32-битного значения (например, битовая маска фичей)
    uint32_t featureSeed = 0xDEADBEEF;
    PrintHexForDashboard(&featureSeed, sizeof(featureSeed), "Feature Seed");

    // Вариант 3: HEX для произвольной строки (например, Bearer-токен)
    std::string secretToken = "Bearer eyJhbGciOiJSUzI1NiJ9.your.token";
    PrintHexForDashboard(secretToken.data(), secretToken.size(), "Bearer Token");

    SecureZeroMemory(&mySecrets, sizeof(mySecrets));
    WipeString(secretToken);
    return 0; */

    // -------------------------------------------------------------------------
    // 1. Инициализация SDK с App Secret из дашборда FoxAuth.
    //    skCrypt() шифрует строковый литерал на этапе компиляции, чтобы он
    //    не присутствовал в бинарнике в открытом виде.
    // -------------------------------------------------------------------------

    std::string appSecret = SK_A("APP_SECRET");
    NebulaFox::Initialize(appSecret);
    WipeString(appSecret); // Затираем из памяти сразу после инициализации

    std::string userKey;
    { auto prompt = std::string(SK_A("Введите лицензионный ключ: ")); std::cout << prompt; WipeString(prompt); }
    std::cin >> userKey;
    { auto msg = std::string(SK_A("\nПодключение к серверам NebulaFox...")); std::cout << msg << std::endl; WipeString(msg); }

    // -------------------------------------------------------------------------
    // 2. Открытие верифицированной сессии.
    //    SDK обращается к бэкенду NebulaFox, проверяет ключ и HWID,
    //    и запечатывает зашифрованный Cloud Payload внутри userSession.
    //    Если этот вызов будет запатчен, хеш сессии сломается и
    //    GetCloudPayload() откажется возвращать данные.
    // -------------------------------------------------------------------------

    NebulaFox::Session userSession;

    if (!NebulaFox::OpenSession(userKey, &userSession)) {
        std::string msg = NebulaFox::GetLastSessionError(userSession);

        if      (msg == SK_A("invalid_key"))        msg = SK_A("Лицензионный ключ не найден.");
        else if (msg == SK_A("key_banned"))          msg = SK_A("Данный ключ заблокирован.");
        else if (msg == SK_A("key_expired"))         msg = SK_A("Срок действия лицензии истёк.");
        else if (msg == SK_A("hwid_mismatch"))       msg = SK_A("Ключ привязан к другому устройству.");
        else if (msg == SK_A("ip_blocked"))          msg = SK_A("Доступ с вашего IP заблокирован.");
        else if (msg == SK_A("ssl_pinning_failed"))  msg = SK_A("Проверка безопасности не пройдена (обнаружен MITM).");
        else if (msg == SK_A("network_error"))       msg = SK_A("Не удалось подключиться к серверу.");

        { auto s = std::string(SK_A("[ОШИБКА]: ")) + msg; std::cout << s << std::endl; WipeString(s); }
        WipeString(msg); WipeString(userKey);
        SafePause(); return 1;
    }

    WipeString(userKey);
    { auto s = std::string(SK_A("Авторизация успешна!")); std::cout << s << std::endl; WipeString(s); }

    // Показываем пользователю дату окончания подписки
    std::string expires = NebulaFox::GetSessionExpires(userSession);
    std::cout << SK_A("Подписка действительна до: ") << expires << std::endl;
    WipeString(expires);

    // -------------------------------------------------------------------------
    // 3. Получение Cloud Payload.
    //
    //    GetCloudPayload() выполняет строгую проверку размера (sizeof).
    //    Перебираем три формата payload по убыванию размера:
    //      а) Полная структура AppSecrets  - все секреты и флаги тарифа
    //      б) Одиночный uint32_t           - лёгкая битовая маска фичей
    //      в) Сырая строка                 - например, Bearer-токен или API-ключ
    //
    //    Используйте тот формат, который соответствует HEX в вашем дашборде.
    // -------------------------------------------------------------------------

    if (!NebulaFox::HasCloudPayload(userSession)) {
        std::cout << SK_A("[-] Предупреждение: Cloud Payload не настроен для этого проекта.") << std::endl;
    }
    else {
        // а) Полная структура: API-ключ + URL бэкенда + ключ шифрования + флаги тарифа
        AppSecrets secrets = {};
        if (NebulaFox::GetCloudPayload(userSession, &secrets, sizeof(secrets))) {
            std::cout << SK_A("[+] Получен полный payload AppSecrets.") << std::endl;
            std::cout << SK_A("    URL бэкенда  : ") << secrets.backendUrl                           << std::endl;
            std::cout << SK_A("    Премиум тариф: ") << (secrets.premiumUnlocked ? "Да" : "Нет")     << std::endl;
            std::cout << SK_A("    Длит. сессии : ") << secrets.sessionTtl << SK_A(" сек")           << std::endl;

            // Используйте secrets.apiKey и secrets.encryptionKey в логике приложения.
            // Не логируйте их - здесь они выводятся только в демонстрационных целях.

            SecureZeroMemory(&secrets, sizeof(secrets)); // Затираем секреты после использования
        }

        // б) Одиночное 32-битное значение: битовая маска доступных функций
        else {
            uint32_t featureMask = 0;
            if (NebulaFox::GetCloudPayload(userSession, &featureMask, sizeof(featureMask))) {
                std::cout << SK_A("[+] Получен payload с маской фичей.") << std::endl;
                std::cout << SK_A("    Флаги: 0x") << std::hex << featureMask << std::dec << std::endl;

                // Пример: проверка отдельных битов маски
                bool hasExport    = (featureMask & (1 << 0)) != 0;
                bool hasApi       = (featureMask & (1 << 1)) != 0;
                bool hasAnalytics = (featureMask & (1 << 2)) != 0;
                std::cout << SK_A("    Экспорт данных: ") << (hasExport    ? "Да" : "Нет") << std::endl;
                std::cout << SK_A("    Доступ к API  : ") << (hasApi       ? "Да" : "Нет") << std::endl;
                std::cout << SK_A("    Аналитика     : ") << (hasAnalytics ? "Да" : "Нет") << std::endl;

                SecureZeroMemory(&featureMask, sizeof(featureMask));
            }

            // в) Сырая строка: например, Bearer-токен или короткий API-ключ (до 63 символов)
            else {
                char tokenBuffer[64] = {};
                if (NebulaFox::GetCloudPayload(userSession, tokenBuffer, sizeof(tokenBuffer) - 1)) {
                    std::cout << SK_A("[+] Получен строковый payload.") << std::endl;
                    // Используйте tokenBuffer как Authorization-заголовок, строку подключения к БД и т.д.
                    // Пример: curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, tokenBuffer);
                    SecureZeroMemory(tokenBuffer, sizeof(tokenBuffer)); // Затираем токен после использования
                }
                else {
                    std::cout << SK_A("[-] Несоответствие размера payload - проверьте структуру и HEX в дашборде.") << std::endl;
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // 4. Закрытие сессии.
    //    CloseSession() вызывает SecureZeroMemory() для всех расшифрованных
    //    данных внутри userSession, исключая их восстановление через дамп памяти.
    // -------------------------------------------------------------------------

    NebulaFox::CloseSession(userSession);
    SafePause();
    return 0;
}
