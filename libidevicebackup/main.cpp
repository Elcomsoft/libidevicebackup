//
//  main.cpp
//  libidevicebackup
//
//  Created by erd on 25.06.21.
//

#include <iostream>
#include <stdio.h>
#include "libidevicebackup.hpp"

int main(int argc, const char * argv[]) {
    printf("start\n");

    /*
    libidevicebackup::doBackup(NULL, ".", [](std::string stage, double progress)->bool{
        printf("[BACKUPINFO] %s: %.2f\n",stage.c_str(),progress);
        return true;
    });
     */
    
    libidevicebackup::enableBackupEncryption(NULL, "123");

    printf("done!\n");
    return 0;
}
