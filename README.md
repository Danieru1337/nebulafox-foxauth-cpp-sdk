# NebulaFox FoxAuth Native C++ SDK

[![C++17](https://img.shields.io/badge/C%2B%2B-17-purple.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64-lightgrey.svg)]()
[![License](https://img.shields.io/badge/License-MIT-blue.svg)]()

NebulaFox (FoxAuth) - платформа для лицензирования
и защиты программного обеспечения. Этот репозиторий содержит официальный
C++ SDK и примеры интеграции для разработчиков.

## Shield Architecture

SDK построен для противодействия реверс-инжинирингу и несанкционированному доступу:

- **Stateful Sessions:** Объекты сессий защищены криптографическими хешами
  FNV1a для предотвращения модификации в памяти.
- **Встроенная криптография:** Ответы сервера подписываются ECDSA P-256,
  payload расшифровывается AES-256 прямо в RAM.
- **Replay Protection:** SDK генерирует уникальный криптографический nonce
  на каждый запрос, исключая эмуляцию локального сервера.
- **SSL Pinning:** Верификация публичного ключа SSL-сертификата защищает
  от MITM-атак.

## Cloud Payload

NebulaFox предоставляет систему **Cloud Payload** - ключевая идея которой
в том, что секретные данные вашего приложения никогда не хранятся внутри
исполняемого файла. Они зашифрованы на серверах NebulaFox и расшифровываются
прямо в RAM клиента только после успешной верификации лицензионного ключа
и HWID устройства. Без валидной лицензии - данные недоступны физически.

Типичные сценарии использования:

- **Серийный ключ или токен стороннего API** (OpenAI, платежный шлюз, и т.д.),
  который не должен быть виден в бинарнике
- **Мастер-ключ шифрования** для расшифровки локальной базы данных приложения
- **Приватный endpoint** вашего backend-сервера, скрытый от анализа трафика
- **Флаги функций** и лимиты, привязанные к конкретному тарифному плану

### Утилита: конвертация структуры в HEX для дашборда

Сервер ожидает данные в HEX-формате. Из-за little-endian архитектуры
байты в памяти хранятся в обратном порядке. Используйте этот сниппет,
чтобы получить корректную HEX-строку для вставки в дашборд NebulaFox:

```cpp
void PrintHexForDashboard(const void* data, size_t size) {
    const BYTE* bytes = static_cast<const BYTE*>(data);
    for (size_t i = 0; i < size; i++) {
        std::cout << std::hex << std::setw(2)
                  << std::setfill('0') << (int)bytes[i];
    }
    std::cout << std::dec << std::endl;
}
```

## Quick Start

### Требования

- **Компилятор:** только x64 (x86 не поддерживается).
- **Подключение:** добавьте `NebulaFox.h` и слинкуйте `sdk.lib`.

### Пример: доставка секретных данных через Cloud Payload

Структура `AppSecrets` описывает данные, которые никогда не попадают
в бинарник. Они хранятся зашифрованными на сервере и передаются в память
процесса только после успешной проверки лицензии и идентификатора устройства.

```cpp
#include <iostream>
#include "NebulaFox.h"

// Секретные данные, доставляемые в RAM только после верификации лицензии.
// Этой структуры не существует в бинарнике до момента успешного OpenSession.
#pragma pack(push, 1)
struct AppSecrets {
    char apiKey[64];        // API-ключ стороннего сервиса (например, платежный шлюз)
    char backendUrl[128];   // Приватный URL вашего backend, скрытый от анализа
    char encryptionKey[32]; // Мастер-ключ AES для расшифровки локальных данных
};
#pragma pack(pop)

int main() {
    // 1. Инициализация с App Secret вашего проекта
    NebulaFox::Initialize("NBL-Your_App_Secret");
    NebulaFox::Session userSession;
    std::string licenseKey = "YOUR-LICENSE-KEY";

    // 2. Верификация лицензии и открытие защищённой сессии
    if (NebulaFox::OpenSession(licenseKey, &userSession)) {

        // 3. Расшифровка и получение секретов из Cloud Payload
        // До этого момента данные существуют только на сервере NebulaFox
        AppSecrets secrets;
        if (NebulaFox::GetCloudPayload(userSession, &secrets, sizeof(secrets))) {
            std::cout << "Backend URL: " << secrets.backendUrl << std::endl;
            // Используйте secrets.apiKey, secrets.encryptionKey и т.д.
            // ...

        } else {
            std::cout << "Error: payload size mismatch." << std::endl;
        }

        // 4. Обязателен: SecureZeroMemory затирает секреты из RAM после работы
        NebulaFox::CloseSession(userSession);

    } else {
        std::cout << "License error: "
                  << NebulaFox::GetLastSessionError(userSession) << std::endl;
    }

    return 0;
}
```

## API Reference

| Функция | Описание |
|---|---|
| `OpenSession(key, &session)` | Верифицирует лицензионный ключ и открывает сессию |
| `HasCloudPayload(session)` | Проверяет наличие Cloud Payload в активной сессии |
| `GetCloudPayload(session, buf, size)` | Копирует payload в буфер со строгой проверкой размера |
| `GetLastSessionError(session)` | Возвращает код ошибки (`invalid_key`, `hwid_mismatch` и др.) |
| `GetSessionExpires(session)` | Дата истечения подписки (`YYYY-MM-DD HH:MM:SS`) |

## Лицензия

MIT - см. файл [LICENSE](LICENSE).
