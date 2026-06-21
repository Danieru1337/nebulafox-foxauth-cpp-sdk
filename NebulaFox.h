#pragma once

#include <string>
#include <vector>
#include <windows.h> 

namespace NebulaFox {

    struct AuthResponse {
        bool success;
        std::string message;
        std::string expires;
        std::vector<BYTE> unlockedData;
    };

 
    class Session {
    public:
        Session();
        ~Session();

        bool IsUsable() const;

    private:
        friend bool OpenSession(const std::string& licenseKey, Session* outSession);
        friend bool HasCloudPayload(const Session& session);
        friend bool GetCloudPayload(Session& session, void* outBuffer, size_t outSize);
        friend std::string GetLastSessionError(const Session& session);
        friend std::string GetSessionExpires(const Session& session);
        friend void CloseSession(Session& session);

        void Reset();
        void Seal();

        bool opened_;
        DWORD guard_;
        std::string lastError_;
        std::string expires_;
        std::vector<BYTE> payload_;
    };

    
    void Initialize(const std::string& appSecret, const std::string& apiUrl = "");
    AuthResponse CheckLicense(const std::string& licenseKey);
    std::string GetHardwareID();

    // API для работы с защищенными сессиями
    bool OpenSession(const std::string& licenseKey, Session* outSession);
    bool HasCloudPayload(const Session& session);
    bool GetCloudPayload(Session& session, void* outBuffer, size_t outSize);
    std::string GetLastSessionError(const Session& session);
    std::string GetSessionExpires(const Session& session);
    void CloseSession(Session& session);
}