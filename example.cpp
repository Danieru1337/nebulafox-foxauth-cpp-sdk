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



// 1. CLOUD PAYLOAD STRUCT (Data-Driven Security)
// #pragma pack(push, 1) prevents the compiler from adding padding bytes for alignment.
// Otherwise the size of this struct in the binary won't match the size of the HEX string
// from the server, and we'll fail with a size mismatch error.
#pragma pack(push, 1)
struct CloudConfig {
    DWORD healthOffset;
    DWORD ammoOffset;
    float damageMultiplier;
    bool  enablePremiumFeatures;
};
#pragma pack(pop)



// 2. HEX string generator for the dashboard
// Reads a variable/struct from memory and outputs a ready-to-use HEX string.
static void PrintHexForDashboard(const void* data, size_t size, const char* label) {
    const BYTE* bytes = static_cast<const BYTE*>(data);
    std::cout << SK_A("[DEV] HEX for ") << label << SK_A(" (") << size << SK_A(" bytes): ");
    for (size_t i = 0; i < size; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)bytes[i];
    }
    std::cout << std::dec << std::endl;
}

// Wipe a string's contents with zeros
static void WipeString(std::string& s) {
    if (!s.empty()) SecureZeroMemory(s.data(), s.capacity());
    s.clear();
}

static void SafePause() {
    { auto s = std::string(SK_A("\nPress any key to exit...")); std::cout << s << std::endl; WipeString(s); }
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    FlushConsoleInputBuffer(hIn);
    char buf[2] = {}; DWORD read = 0;
    ReadConsoleA(hIn, buf, 1, &read, NULL);
    SecureZeroMemory(buf, sizeof(buf));
}


// 3. MAIN LOGIC
int main() {
    SetConsoleTitleA(SK_A("FoxAuth"));
    // PAYLOAD GENERATOR
    // Uncomment, generate the hex, paste it into the FoxAuth dashboard, then comment out again

    /* std::cout << "DEV TOOL" << std::endl;

    // Option 1: Generate HEX for a plain seed (e.g. to XOR addresses later)
    DWORD mySeed = 2;
    PrintHexForDashboard(&mySeed, sizeof(mySeed), "Seed (2)");
    // Output: 02000000 - paste it directly into the web dashboard

    // Option 2: Generate HEX for an entire struct with offsets
    CloudConfig myConfig = { 0x10A2B, 0x14F0, 2.5f, true };
    PrintHexForDashboard(&myConfig, sizeof(myConfig), "CloudConfig Struct");
    // Output: 2b0a0100f01400000000204001

    // Option 3: If you want to store a plain string in the cloud payload
    std::string myStr = "FoxAuth_Secret";
    PrintHexForDashboard(myStr.data(), myStr.size(), "String");
    // Output: 466f78417574685f536563726574
    */


    // 1. Initialize the SDK (paste your App Secret from the dashboard here)
    std::string appSecret = SK_A("NBL-80889383e3be32feb5dbc5e899867e5c");
    NebulaFox::Initialize(appSecret);
    WipeString(appSecret);

    std::string userKey;
    { auto key = std::string(SK_A("Enter license key: ")); std::cout << key; WipeString(key); }
    std::cin >> userKey;

    { auto msg = std::string(SK_A("\nConnecting to NebulaFox servers...")); std::cout << msg << std::endl; WipeString(msg); }

    // AUTHORIZATION
    NebulaFox::Session userSession;

    // Contact the backend. If the key is valid, our payload from the server gets sealed
    // inside userSession. If someone patches out this check, the hash inside the session
    // breaks and they won't be able to retrieve the payload.
    if (!NebulaFox::OpenSession(userKey, &userSession)) {

        std::string msg = NebulaFox::GetLastSessionError(userSession);

        if (msg == SK_A("invalid_key"))                 msg = SK_A("License key not found.");
        else if (msg == SK_A("key_banned"))             msg = SK_A("This key has been banned.");
        else if (msg == SK_A("key_expired"))            msg = SK_A("License has expired.");
        else if (msg == SK_A("hwid_mismatch"))          msg = SK_A("This key is bound to another device.");
        else if (msg == SK_A("ip_blocked"))             msg = SK_A("Access from your IP is blocked.");
        else if (msg == SK_A("ssl_pinning_failed"))     msg = SK_A("Security check failed (MITM detected).");
        else if (msg == SK_A("network_error"))          msg = SK_A("Could not connect to the server.");

        { auto s = std::string(SK_A("[ERROR]: ")) + msg; std::cout << s << std::endl; WipeString(s); }
        WipeString(msg); WipeString(userKey);
        SafePause(); return 1;
    }
    WipeString(userKey);

    { auto s = std::string(SK_A("Authorization successful!")); std::cout << s << std::endl; WipeString(s); }

    // Show the user when their subscription expires
    std::string expires = NebulaFox::GetSessionExpires(userSession);
    std::cout << SK_A("Subscription expires: ") << expires << std::endl;
    WipeString(expires);

    // RETRIEVE THE CLOUD PAYLOAD
    if (!NebulaFox::HasCloudPayload(userSession)) {
        std::cout << SK_A("[-] Warning: No Cloud Payload received from server.") << std::endl;
    }
    else {
        // GetCloudPayload performs strict size validation (sizeof).

        // 1: Try to retrieve the entire struct (e.g. fresh offsets)
        CloudConfig cfg;
        if (NebulaFox::GetCloudPayload(userSession, &cfg, sizeof(cfg))) {
            std::cout << SK_A("[+] Received Struct Payload from cloud!") << std::endl;
            std::cout << SK_A("    Health Offset: 0x") << std::hex << cfg.healthOffset << std::dec << std::endl;
            std::cout << SK_A("    Ammo Offset:   0x") << std::hex << cfg.ammoOffset << std::dec << std::endl;
            std::cout << SK_A("    Premium:       ") << (cfg.enablePremiumFeatures ? "Yes" : "No") << std::endl;
        }
        // 2: If the size doesn't match, maybe it's just a 4-byte XOR seed?
        else {
            DWORD seed = 0;
            if (NebulaFox::GetCloudPayload(userSession, &seed, sizeof(seed))) {
                std::cout << SK_A("[+] Received Seed Payload (4 bytes)!") << std::endl;
                std::cout << SK_A("    Dynamic Seed: ") << seed << std::endl;
            }
            // 3: If that didn't work either, try reading it as a plain string (buffer size = 14)
            else {
                char strBuffer[15] = {};
                if (NebulaFox::GetCloudPayload(userSession, strBuffer, 14)) {
                    std::cout << SK_A("[+] Received String Payload!") << std::endl;
                    std::cout << SK_A("    String: ") << strBuffer << std::endl;
                }
                else {
                    std::cout << SK_A("[-] Payload size mismatch or integrity compromised!") << std::endl;
                }
            }
        }
    }


    // CLOSE THE SESSION
    NebulaFox::CloseSession(userSession);

    SafePause();
    return 0;
}
