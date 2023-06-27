//
//  libidevicebackup.hpp
//  libidevicebackup
//
//  Created by erd on 25.06.21.
//

#ifndef libidevicebackup_hpp
#define libidevicebackup_hpp

#include <iostream>
#include <functional>

namespace libidevicebackup {
    using ProgressCallback = std::function<bool(std::string stage, double progress)>;

    void doBackup(const char *udid, const char *dstPath, ProgressCallback callback = nullptr);
    void enableBackupEncryption(const char *udid, std::string backupPassword);
    void disableBackupEncryption(const char *udid, std::string backupPassword);
    void changeBackupEncryptionPassword(const char *udid, std::string oldPassword, std::string newPassword);
    bool isBackupPasswordEnabled(const char *udid);
}

#endif /* libidevicebackup_hpp */
