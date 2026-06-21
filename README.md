# nebulafox-foxauth-cpp-sdk
Official C++ SDK and integration examples for NebulaFox - SaaS Licensing and Software Protection Platform.
Markdown
# NebulaFox Native C++ SDK

![C++17](https://img.shields.io/badge/C%2B%2B-17-purple.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20x64-lightgrey.svg)
![License](https://img.shields.io/badge/License-MIT-blue.svg)

**NebulaFox** (FoxAuth) is an enterprise-grade SaaS Licensing and Software Protection platform. This repository contains the official C++ SDK documentation and integration examples for developers.

## 🛡️ Security Architecture
Our SDK is built to prevent reverse-engineering and unauthorized access:
* **Stateful Sessions:** Session objects are protected by FNV1a cryptographic hashes to prevent memory tampering.
* **Built-in Cryptography:** Server responses are signed with ECDSA P-256 and include a random AES-256 key. Payloads are decrypted directly in RAM.
* **Replay Protection:** The SDK generates a random cryptographic Nonce per request to prevent local server emulation.
* **SSL Pinning:** Prevents MITM attacks by verifying the SSL certificate's public key hash.

## ☁️ Data-Driven Security (Cloud Payload)
NebulaFox provides a unique **Cloud Payload** system. You can remove critical variables (offsets, decryption seeds, API tokens) from your application's source code and store them securely on our servers. 

### Utility: Convert Struct to HEX for Dashboard
The server expects data in HEX format. Because of the Little Endian architecture, bytes in memory are stored in reverse order. Use this snippet to get the correct HEX string for the NebulaFox dashboard:
```cpp
void PrintHexForDashboard(const void* data, size_t size) {
    const BYTE* bytes = static_cast<const BYTE*>(data);
    for (size_t i = 0; i < size; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)bytes[i];
    }
    std::cout << std::dec << std::endl;
}
🚀 Quick Start & Integration
Requirements
Compiler: Set to x64 (x86 architecture is not supported).

Include: Add NebulaFox.h and link sdk.lib in your linker settings.

Example: Struct Extraction (Strict Size Control)
The most secure method for integration. Describe your configuration struct and retrieve it entirely from the secure session.

C++
#include <iostream>
#include "NebulaFox.h"

#pragma pack(push, 1)
struct CloudConfig {
    DWORD healthOffset;
    DWORD ammoOffset;
    float damageMultiplier;
    bool  enablePremium;
};
#pragma pack(pop)

int main() {
    // 1. Initialize with your App Secret
    NebulaFox::Initialize("NBL-App_Secret");
    NebulaFox::Session userSession;
    std::string userKey = "YOUR-LICENSE-KEY";

    // 2. Open secure session
    if (NebulaFox::OpenSession(userKey, &userSession)) {
        CloudConfig cfg;
        
        // 3. Extract Cloud Payload with strict size matching
        if (NebulaFox::GetCloudPayload(userSession, &cfg, sizeof(cfg))) {
            std::cout << "Health Offset: " << std::hex << cfg.healthOffset << std::endl;
        } else {
            std::cout << "Error: Payload size mismatch!" << std::endl;
        }

        // 4. Mandatory: Securely close session (wipes decrypted memory)
        NebulaFox::CloseSession(userSession);
    } else {
        std::cout << "Error: " << NebulaFox::GetLastSessionError(userSession) << std::endl;
    }

    return 0;
}
📚 API Reference
OpenSession(key, &session) — Sends a network request, verifies the response, and opens a session.

HasCloudPayload(session) — Checks if the active session contains an encrypted Cloud Payload.

GetCloudPayload(session, buffer, size) — Copies the payload into your buffer with strict size validation.

GetLastSessionError(session) — Returns the error string (e.g., invalid_key or hwid_mismatch).

GetSessionExpires(session) — Returns the subscription expiration date (YYYY-MM-DD HH:MM:SS).

CloseSession(session) — Mandatory. Uses SecureZeroMemory to wipe decrypted data inside the object to protect against memory dumping.
