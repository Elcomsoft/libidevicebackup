//
//  libidevicebackup.cpp
//  libidevicebackup
//
//  Created by erd on 25.06.21.
//

#include "../include/libidevicebackup/libidevicebackup.hpp"

/*
 * idevicebackup2.c
 * Command line interface to use the device's backup and restore service
 *
 * Copyright (c) 2010-2019 Nikias Bassen, All Rights Reserved.
 * Copyright (c) 2009-2010 Martin Szulecki, All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define TOOL_NAME "idevicebackup2"
#include <libgeneral/macros.h>
#include "../include/libidevicebackup/IBKPexception.hpp"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <libgen.h>
#include <ctype.h>
#include <time.h>

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/mobilebackup2.h>
#include <libimobiledevice/notification_proxy.h>
#include <libimobiledevice/afc.h>
#include <libimobiledevice/installation_proxy.h>
#include <libimobiledevice/sbservices.h>
#include <libimobiledevice/diagnostics_relay.h>
#include <plist/plist.h>

extern "C"{
#include <libimobiledevice-glue/utils.h>
}

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#elif defined(HAVE_WINSOCK_H)
#include <winsock.h>
#endif


#define LOCK_ATTEMPTS 50
#define LOCK_WAIT 200000

#ifdef WIN32
#include <windows.h>
#include <conio.h>
#define sleep(x) Sleep(x*1000)
#ifndef ELOOP
#define ELOOP 114
#endif
#else
#include <termios.h>
#include <sys/statvfs.h>
#endif
#include <sys/stat.h>

#define CODE_SUCCESS 0x00
#define CODE_ERROR_LOCAL 0x06
#define CODE_ERROR_REMOTE 0x0b
#define CODE_FILE_DATA 0x0c

#define DEVICE_VERSION(maj, min, patch) (((maj & 0xFF) << 16) | ((min & 0xFF) << 8) | (patch & 0xFF))


static int verbose = 1;

#define PRINT_VERBOSE(min_level, ...) if (verbose >= min_level) { printf(__VA_ARGS__); };

enum cmd_mode {
    CMD_BACKUP,
    CMD_RESTORE,
    CMD_INFO,
    CMD_LIST,
    CMD_UNBACK,
    CMD_CHANGEPW,
    CMD_LEAVE,
    CMD_CLOUD
};

enum cmd_flags {
    CMD_FLAG_RESTORE_SYSTEM_FILES       = (1 << 1),
    CMD_FLAG_RESTORE_NO_REBOOT          = (1 << 2),
    CMD_FLAG_RESTORE_COPY_BACKUP        = (1 << 3),
    CMD_FLAG_RESTORE_SETTINGS           = (1 << 4),
    CMD_FLAG_RESTORE_REMOVE_ITEMS       = (1 << 5),
    CMD_FLAG_ENCRYPTION_ENABLE          = (1 << 6),
    CMD_FLAG_ENCRYPTION_DISABLE         = (1 << 7),
    CMD_FLAG_ENCRYPTION_CHANGEPW        = (1 << 8),
    CMD_FLAG_FORCE_FULL_BACKUP          = (1 << 9),
    CMD_FLAG_CLOUD_ENABLE               = (1 << 10),
    CMD_FLAG_CLOUD_DISABLE              = (1 << 11),
    CMD_FLAG_RESTORE_SKIP_APPS          = (1 << 12)
};

#ifdef DEBUG_PLIST
#define MAX_PRINT_LEN 64*1024
void debug_plist(plist_t plist) {
    uint32_t size = 0;
    char* data = NULL;
    plist_to_xml(plist, &data, &size);
    if (size <= MAX_PRINT_LEN)
        info("%s:printing %i bytes plist:\n%s", __FILE__, size, data);
    else
        info("%s:supressed printing %i bytes plist...\n", __FILE__, size);
    free(data);
}
#undef MAX_PRINT_LEN
#endif

struct backupState{
    libidevicebackup::ProgressCallback callback;
    int quit_flag;
    double overall_progress;
};

static void notify_cb(const char *notification, void *userdata){
    int *quit_flag = (int*)userdata;
    if (strlen(notification) == 0) {
        return;
    }
    if (!strcmp(notification, NP_SYNC_CANCEL_REQUEST)) {
        PRINT_VERBOSE(1, "User has cancelled the backup process on the device.\n");
        (*quit_flag)++;
    } else if (!strcmp(notification, NP_BACKUP_DOMAIN_CHANGED)) {
        warning("Backup domain changed!");
    } else {
        PRINT_VERBOSE(1, "Unhandled notification '%s' (TODO: implement)\n", notification);
    }
}

static void mobilebackup_afc_get_file_contents(afc_client_t afc, const char *filename, char **data, uint64_t *size)
{
    if (!afc || !data || !size) {
        return;
    }

    char **fileinfo = NULL;
    size_t fsize = 0;

    afc_get_file_info(afc, filename, &fileinfo);
    if (!fileinfo) {
        return;
    }
    int i;
    for (i = 0; fileinfo[i]; i+=2) {
        if (!strcmp(fileinfo[i], "st_size")) {
            fsize = atol(fileinfo[i+1]);
            break;
        }
    }
    afc_dictionary_free(fileinfo);

    if (fsize == 0) {
        return;
    }

    uint64_t f = 0;
    afc_file_open(afc, filename, AFC_FOPEN_RDONLY, &f);
    if (!f) {
        return;
    }
    char *buf = (char*)malloc(fsize);
    uint32_t done = 0;
    while (done < fsize) {
        uint32_t bread = 0;
        afc_file_read(afc, f, buf+done, 65536, &bread);
        if (bread > 0) {
            done += bread;
        } else {
            break;
        }
    }
    if (done == fsize) {
        *size = fsize;
        *data = buf;
    } else {
        free(buf);
    }
    afc_file_close(afc, f);
}

static int __mkdir(const char* path, int mode)
{
#ifdef WIN32
    return mkdir(path);
#else
    return mkdir(path, mode);
#endif
}

static int mkdir_with_parents(const char *dir, int mode)
{
    if (!dir) return -1;
    if (__mkdir(dir, mode) == 0) {
        return 0;
    } else {
        if (errno == EEXIST) return 0;
    }
    int res;
    char *parent = strdup(dir);
    char *parentdir = dirname(parent);
    if (parentdir) {
        res = mkdir_with_parents(parentdir, mode);
    } else {
        res = -1;
    }
    free(parent);
    if (res == 0) {
        mkdir_with_parents(dir, mode);
    }
    return res;
}

#ifdef WIN32
static int win32err_to_errno(int err_value)
{
    switch (err_value) {
        case ERROR_FILE_NOT_FOUND:
            return ENOENT;
        case ERROR_ALREADY_EXISTS:
            return EEXIST;
        default:
            return EFAULT;
    }
}
#endif

static int remove_file(const char* path)
{
    int e = 0;
#ifdef WIN32
    if (!DeleteFile(path)) {
        e = win32err_to_errno(GetLastError());
    }
#else
    if (remove(path) < 0) {
        e = errno;
    }
#endif
    return e;
}

static int remove_directory(const char* path)
{
    int e = 0;
#ifdef WIN32
    if (!RemoveDirectory(path)) {
        e = win32err_to_errno(GetLastError());
    }
#else
    if (remove(path) < 0) {
        e = errno;
    }
#endif
    return e;
}

struct entry {
    char *name;
    struct entry *next;
};

static void scan_directory(const char *path, struct entry **files, struct entry **directories)
{
    DIR* cur_dir = opendir(path);
    if (cur_dir) {
        struct dirent* ep;
        while ((ep = readdir(cur_dir))) {
            if ((strcmp(ep->d_name, ".") == 0) || (strcmp(ep->d_name, "..") == 0)) {
                continue;
            }
            char *fpath = string_build_path(path, ep->d_name, NULL);
            if (fpath) {
#ifdef HAVE_DIRENT_D_TYPE
                if (ep->d_type & DT_DIR) {
#else
                struct stat st;
                if (stat(fpath, &st) != 0) return;
                if (S_ISDIR(st.st_mode)) {
#endif
                    struct entry *ent = (struct entry *)malloc(sizeof(struct entry));
                    if (!ent) return;
                    ent->name = fpath;
                    ent->next = *directories;
                    *directories = ent;
                    scan_directory(fpath, files, directories);
                    fpath = NULL;
                } else {
                    struct entry *ent = (struct entry *)malloc(sizeof(struct entry));
                    if (!ent) return;
                    ent->name = fpath;
                    ent->next = *files;
                    *files = ent;
                    fpath = NULL;
                }
            }
        }
        closedir(cur_dir);
    }
}

static int rmdir_recursive(const char* path)
{
    int res = 0;
    struct entry *files = NULL;
    struct entry *directories = NULL;
    struct entry *ent;

    ent = (struct entry *)malloc(sizeof(struct entry));
    if (!ent) return ENOMEM;
    ent->name = strdup(path);
    ent->next = NULL;
    directories = ent;

    scan_directory(path, &files, &directories);

    ent = files;
    while (ent) {
        struct entry *del = ent;
        res = remove_file(ent->name);
        free(ent->name);
        ent = ent->next;
        free(del);
    }
    ent = directories;
    while (ent) {
        struct entry *del = ent;
        res = remove_directory(ent->name);
        free(ent->name);
        ent = ent->next;
        free(del);
    }

    return res;
}

static char* get_uuid()
{
    const char *chars = "ABCDEF0123456789";
    int i = 0;
    char *uuid = (char*)malloc(sizeof(char) * 33);

    srand((unsigned)time(NULL));

    for (i = 0; i < 32; i++) {
        uuid[i] = chars[rand() % 16];
    }

    uuid[32] = '\0';

    return uuid;
}

static plist_t mobilebackup_factory_info_plist_new(const char* udid, idevice_t device, afc_client_t afc)
{
    /* gather data from lockdown */
    plist_t value_node = NULL;
    plist_t root_node = NULL;
    plist_t itunes_settings = NULL;
    plist_t min_itunes_version = NULL;
    char *udid_uppercase = NULL;

    lockdownd_client_t lockdown = NULL;
    if (lockdownd_client_new_with_handshake(device, &lockdown, TOOL_NAME) != LOCKDOWN_E_SUCCESS) {
        return NULL;
    }

    plist_t ret = plist_new_dict();

    /* get basic device information in one go */
    lockdownd_get_value(lockdown, NULL, NULL, &root_node);

    /* get iTunes settings */
    lockdownd_get_value(lockdown, "com.apple.iTunes", NULL, &itunes_settings);

    /* get minimum iTunes version */
    lockdownd_get_value(lockdown, "com.apple.mobile.iTunes", "MinITunesVersion", &min_itunes_version);

    lockdownd_client_free(lockdown);

    /* get a list of installed user applications */
    plist_t app_dict = plist_new_dict();
    plist_t installed_apps = plist_new_array();
    instproxy_client_t ip = NULL;
    if (instproxy_client_start_service(device, &ip, TOOL_NAME) == INSTPROXY_E_SUCCESS) {
        plist_t client_opts = instproxy_client_options_new();
        instproxy_client_options_add(client_opts, "ApplicationType", "User", NULL);
        instproxy_client_options_set_return_attributes(client_opts, "CFBundleIdentifier", "ApplicationSINF", "iTunesMetadata", NULL);

        plist_t apps = NULL;
        instproxy_browse(ip, client_opts, &apps);

        sbservices_client_t sbs = NULL;
        if (sbservices_client_start_service(device, &sbs, TOOL_NAME) != SBSERVICES_E_SUCCESS) {
            printf("Couldn't establish sbservices connection. Continuing anyway.\n");
        }

        if (apps && (plist_get_node_type(apps) == PLIST_ARRAY)) {
            uint32_t app_count = plist_array_get_size(apps);
            uint32_t i;
            for (i = 0; i < app_count; i++) {
                plist_t app_entry = plist_array_get_item(apps, i);
                plist_t bundle_id = plist_dict_get_item(app_entry, "CFBundleIdentifier");
                if (bundle_id) {
                    char *bundle_id_str = NULL;
                    plist_array_append_item(installed_apps, plist_copy(bundle_id));

                    plist_get_string_val(bundle_id, &bundle_id_str);
                    plist_t sinf = plist_dict_get_item(app_entry, "ApplicationSINF");
                    plist_t meta = plist_dict_get_item(app_entry, "iTunesMetadata");
                    if (sinf && meta) {
                        plist_t adict = plist_new_dict();
                        plist_dict_set_item(adict, "ApplicationSINF", plist_copy(sinf));
                        if (sbs) {
                            char *pngdata = NULL;
                            uint64_t pngsize = 0;
                            sbservices_get_icon_pngdata(sbs, bundle_id_str, &pngdata, &pngsize);
                            if (pngdata) {
                                plist_dict_set_item(adict, "PlaceholderIcon", plist_new_data(pngdata, pngsize));
                                free(pngdata);
                            }
                        }
                        plist_dict_set_item(adict, "iTunesMetadata", plist_copy(meta));
                        plist_dict_set_item(app_dict, bundle_id_str, adict);
                    }
                    free(bundle_id_str);
                }
            }
        }
        plist_free(apps);

        if (sbs) {
            sbservices_client_free(sbs);
        }

        instproxy_client_options_free(client_opts);

        instproxy_client_free(ip);
    }

    /* Applications */
    plist_dict_set_item(ret, "Applications", app_dict);

    /* set fields we understand */
    value_node = plist_dict_get_item(root_node, "BuildVersion");
    plist_dict_set_item(ret, "Build Version", plist_copy(value_node));

    value_node = plist_dict_get_item(root_node, "DeviceName");
    plist_dict_set_item(ret, "Device Name", plist_copy(value_node));
    plist_dict_set_item(ret, "Display Name", plist_copy(value_node));

    char *uuid = get_uuid();
    plist_dict_set_item(ret, "GUID", plist_new_string(uuid));
    free(uuid);

    value_node = plist_dict_get_item(root_node, "IntegratedCircuitCardIdentity");
    if (value_node)
        plist_dict_set_item(ret, "ICCID", plist_copy(value_node));

    value_node = plist_dict_get_item(root_node, "IntegratedCircuitCardIdentity2");
    if (value_node)
        plist_dict_set_item(ret, "ICCID2", plist_copy(value_node));
    
    value_node = plist_dict_get_item(root_node, "InternationalMobileEquipmentIdentity");
    if (value_node)
        plist_dict_set_item(ret, "IMEI", plist_copy(value_node));

    value_node = plist_dict_get_item(root_node, "InternationalMobileEquipmentIdentity2");
        if (value_node)
            plist_dict_set_item(ret, "IMEI2", plist_copy(value_node));
    
    /* Installed Applications */
    plist_dict_set_item(ret, "Installed Applications", installed_apps);

    plist_dict_set_item(ret, "Last Backup Date", plist_new_date((int32_t)(time(NULL) - MAC_EPOCH), 0));

    value_node = plist_dict_get_item(root_node, "MobileEquipmentIdentifier");
    if (value_node)
        plist_dict_set_item(ret, "MEID", plist_copy(value_node));

    value_node = plist_dict_get_item(root_node, "PhoneNumber");
    if (value_node && (plist_get_node_type(value_node) == PLIST_STRING)) {
        plist_dict_set_item(ret, "Phone Number", plist_copy(value_node));
    }

    /* FIXME Product Name */

    value_node = plist_dict_get_item(root_node, "ProductType");
    plist_dict_set_item(ret, "Product Type", plist_copy(value_node));

    value_node = plist_dict_get_item(root_node, "ProductVersion");
    plist_dict_set_item(ret, "Product Version", plist_copy(value_node));

    value_node = plist_dict_get_item(root_node, "SerialNumber");
    plist_dict_set_item(ret, "Serial Number", plist_copy(value_node));

    /* FIXME Sync Settings? */

    value_node = plist_dict_get_item(root_node, "UniqueDeviceID");
    plist_dict_set_item(ret, "Target Identifier", plist_new_string(udid));

    plist_dict_set_item(ret, "Target Type", plist_new_string("Device"));

    /* uppercase */
    udid_uppercase = string_toupper((char*)udid);
    plist_dict_set_item(ret, "Unique Identifier", plist_new_string(udid_uppercase));
    free(udid_uppercase);

    char *data_buf = NULL;
    uint64_t data_size = 0;
    mobilebackup_afc_get_file_contents(afc, "/Books/iBooksData2.plist", &data_buf, &data_size);
    if (data_buf) {
        plist_dict_set_item(ret, "iBooks Data 2", plist_new_data(data_buf, data_size));
        free(data_buf);
    }

    plist_t files = plist_new_dict();
    const char *itunesfiles[] = {
        "ApertureAlbumPrefs",
        "IC-Info.sidb",
        "IC-Info.sidv",
        "PhotosFolderAlbums",
        "PhotosFolderName",
        "PhotosFolderPrefs",
        "VoiceMemos.plist",
        "iPhotoAlbumPrefs",
        "iTunesApplicationIDs",
        "iTunesPrefs",
        "iTunesPrefs.plist",
        NULL
    };
    int i = 0;
    for (i = 0; itunesfiles[i]; i++) {
        data_buf = NULL;
        data_size = 0;
        char *fname = (char*)malloc(strlen("/iTunes_Control/iTunes/") + strlen(itunesfiles[i]) + 1);
        strcpy(fname, "/iTunes_Control/iTunes/");
        strcat(fname, itunesfiles[i]);
        mobilebackup_afc_get_file_contents(afc, fname, &data_buf, &data_size);
        free(fname);
        if (data_buf) {
            plist_dict_set_item(files, itunesfiles[i], plist_new_data(data_buf, data_size));
            free(data_buf);
        }
    }
    plist_dict_set_item(ret, "iTunes Files", files);

    plist_dict_set_item(ret, "iTunes Settings", itunes_settings ? plist_copy(itunes_settings) : plist_new_dict());

    /* since we usually don't have iTunes, let's get the minimum required iTunes version from the device */
    if (min_itunes_version) {
        plist_dict_set_item(ret, "iTunes Version", plist_copy(min_itunes_version));
    } else {
        plist_dict_set_item(ret, "iTunes Version", plist_new_string("10.0.1"));
    }

    plist_free(itunes_settings);
    plist_free(min_itunes_version);
    plist_free(root_node);

    return ret;
}

static int mb2_status_check_snapshot_state(const char *path, const char *udid, const char *matches)
{
    int ret = 0;
    plist_t status_plist = NULL;
    char *file_path = string_build_path(path, udid, "Status.plist", NULL);

    plist_read_from_file(file_path, &status_plist, NULL);
    free(file_path);
    if (!status_plist) {
        printf("Could not read Status.plist!\n");
        return ret;
    }
    plist_t node = plist_dict_get_item(status_plist, "SnapshotState");
    if (node && (plist_get_node_type(node) == PLIST_STRING)) {
        char* sval = NULL;
        plist_get_string_val(node, &sval);
        if (sval) {
            ret = (strcmp(sval, matches) == 0) ? 1 : 0;
            free(sval);
        }
    } else {
        printf("%s: ERROR could not get SnapshotState key from Status.plist!\n", __func__);
    }
    plist_free(status_plist);
    return ret;
}

static void do_post_notification(idevice_t device, const char *notification)
{
    lockdownd_service_descriptor_t service = NULL;
    np_client_t np;

    lockdownd_client_t lockdown = NULL;

    if (lockdownd_client_new_with_handshake(device, &lockdown, TOOL_NAME) != LOCKDOWN_E_SUCCESS) {
        return;
    }

    lockdownd_start_service(lockdown, NP_SERVICE_NAME, &service);
    if (service && service->port) {
        np_client_new(device, service, &np);
        if (np) {
            np_post_notification(np, notification);
            np_client_free(np);
        }
    } else {
        printf("Could not start %s\n", NP_SERVICE_NAME);
    }

    if (service) {
        lockdownd_service_descriptor_free(service);
        service = NULL;
    }
    lockdownd_client_free(lockdown);
}

static void mb2_set_overall_progress(double progress, backupState *bstate)
{
    if (progress <= 0.0)
        bstate->overall_progress = 0;
    else if (progress >= 100.0f)
        bstate->overall_progress = 100.0f;
    else
        bstate->overall_progress = progress;
}

static void mb2_set_overall_progress_from_message(plist_t message, char* identifier, backupState *bstate)
{
    plist_t node = NULL;
    double progress = 0.0;

    if (!strcmp(identifier, "DLMessageDownloadFiles")) {
        node = plist_array_get_item(message, 3);
    } else if (!strcmp(identifier, "DLMessageUploadFiles")) {
        node = plist_array_get_item(message, 2);
    } else if (!strcmp(identifier, "DLMessageMoveFiles") || !strcmp(identifier, "DLMessageMoveItems")) {
        node = plist_array_get_item(message, 3);
    } else if (!strcmp(identifier, "DLMessageRemoveFiles") || !strcmp(identifier, "DLMessageRemoveItems")) {
        node = plist_array_get_item(message, 3);
    }

    if (node != NULL) {
        plist_get_real_val(node, &progress);
        mb2_set_overall_progress(progress, bstate);
    }
}

static void mb2_multi_status_add_file_error(plist_t status_dict, const char *path, int error_code, const char *error_message)
{
    if (!status_dict) return;
    plist_t filedict = plist_new_dict();
    plist_dict_set_item(filedict, "DLFileErrorString", plist_new_string(error_message));
    plist_dict_set_item(filedict, "DLFileErrorCode", plist_new_uint(error_code));
    plist_dict_set_item(status_dict, path, filedict);
}

static int errno_to_device_error(int errno_value)
{
    switch (errno_value) {
        case ENOENT:
            return -6;
        case EEXIST:
            return -7;
        case ENOTDIR:
            return -8;
        case EISDIR:
            return -9;
        case ELOOP:
            return -10;
        case EIO:
            return -11;
        case ENOSPC:
            return -15;
        default:
            return -1;
    }
}

static int mb2_handle_send_file(mobilebackup2_client_t mobilebackup2, const char *backup_dir, const char *path, plist_t *errplist)
{
    uint32_t nlen = 0;
    uint32_t pathlen = (uint32_t)strlen(path);
    uint32_t bytes = 0;
    char *localfile = string_build_path(backup_dir, path, NULL);
    char buf[32768];
#ifdef WIN32
    struct _stati64 fst;
#else
    struct stat fst;
#endif

    FILE *f = NULL;
    uint32_t slen = 0;
    int errcode = -1;
    int result = -1;
    uint32_t length;
#ifdef WIN32
    uint64_t total;
    uint64_t sent;
#else
    off_t total;
    off_t sent;
#endif

    mobilebackup2_error_t err;

    /* send path length */
    nlen = htonl(pathlen);
    err = mobilebackup2_send_raw(mobilebackup2, (const char*)&nlen, sizeof(nlen), &bytes);
    if (err != MOBILEBACKUP2_E_SUCCESS) {
        goto leave_proto_err;
    }
    if (bytes != (uint32_t)sizeof(nlen)) {
        err = MOBILEBACKUP2_E_MUX_ERROR;
        goto leave_proto_err;
    }

    /* send path */
    err = mobilebackup2_send_raw(mobilebackup2, path, pathlen, &bytes);
    if (err != MOBILEBACKUP2_E_SUCCESS) {
        goto leave_proto_err;
    }
    if (bytes != pathlen) {
        err = MOBILEBACKUP2_E_MUX_ERROR;
        goto leave_proto_err;
    }

#ifdef WIN32
    if (_stati64(localfile, &fst) < 0)
#else
    if (stat(localfile, &fst) < 0)
#endif
    {
        if (errno != ENOENT)
            printf("%s: stat failed on '%s': %d\n", __func__, localfile, errno);
        errcode = errno;
        goto leave;
    }

    total = fst.st_size;

    {
        char *format_size = string_format_size(total);
        PRINT_VERBOSE(1, "Sending '%s' (%s)\n", path, format_size);
        free(format_size);
    }

    if (total == 0) {
        errcode = 0;
        goto leave;
    }

    f = fopen(localfile, "rb");
    if (!f) {
        printf("%s: Error opening local file '%s': %d\n", __func__, localfile, errno);
        errcode = errno;
        goto leave;
    }

    sent = 0;
    do {
        length = (uint32_t)(((total-sent) < (long long)sizeof(buf)) ? (uint32_t)total-sent : (uint32_t)sizeof(buf));
        /* send data size (file size + 1) */
        nlen = htonl(length+1);
        memcpy(buf, &nlen, sizeof(nlen));
        buf[4] = CODE_FILE_DATA;
        err = mobilebackup2_send_raw(mobilebackup2, (const char*)buf, 5, &bytes);
        if (err != MOBILEBACKUP2_E_SUCCESS) {
            goto leave_proto_err;
        }
        if (bytes != 5) {
            goto leave_proto_err;
        }

        /* send file contents */
        size_t r = fread(buf, 1, sizeof(buf), f);
        if (r <= 0) {
            printf("%s: read error\n", __func__);
            errcode = errno;
            goto leave;
        }
        err = mobilebackup2_send_raw(mobilebackup2, buf, (uint32_t)r, &bytes);
        if (err != MOBILEBACKUP2_E_SUCCESS) {
            goto leave_proto_err;
        }
        if (bytes != (uint32_t)r) {
            printf("Error: sent only %d of %d bytes\n", bytes, (int)r);
            goto leave_proto_err;
        }
        sent += r;
    } while (sent < total);
    fclose(f);
    f = NULL;
    errcode = 0;

leave:
    if (errcode == 0) {
        result = 0;
        nlen = 1;
        nlen = htonl(nlen);
        memcpy(buf, &nlen, 4);
        buf[4] = CODE_SUCCESS;
        mobilebackup2_send_raw(mobilebackup2, buf, 5, &bytes);
    } else {
        if (!*errplist) {
            *errplist = plist_new_dict();
        }
        char *errdesc = strerror(errcode);
        mb2_multi_status_add_file_error(*errplist, path, errno_to_device_error(errcode), errdesc);

        length = (uint32_t)strlen(errdesc);
        nlen = htonl(length+1);
        memcpy(buf, &nlen, 4);
        buf[4] = CODE_ERROR_LOCAL;
        slen = 5;
        memcpy(buf+slen, errdesc, length);
        slen += length;
        err = mobilebackup2_send_raw(mobilebackup2, (const char*)buf, slen, &bytes);
        if (err != MOBILEBACKUP2_E_SUCCESS) {
            printf("could not send message\n");
        }
        if (bytes != slen) {
            printf("could only send %d from %d\n", bytes, slen);
        }
    }

leave_proto_err:
    if (f)
        fclose(f);
    free(localfile);
    return result;
}

static void mb2_handle_send_files(mobilebackup2_client_t mobilebackup2, plist_t message, const char *backup_dir)
{
    uint32_t cnt;
    uint32_t i = 0;
    uint32_t sent;
    plist_t errplist = NULL;

    if (!message || (plist_get_node_type(message) != PLIST_ARRAY) || (plist_array_get_size(message) < 2) || !backup_dir) return;

    plist_t files = plist_array_get_item(message, 1);
    cnt = plist_array_get_size(files);

    for (i = 0; i < cnt; i++) {
        plist_t val = plist_array_get_item(files, i);
        if (plist_get_node_type(val) != PLIST_STRING) {
            continue;
        }
        char *str = NULL;
        plist_get_string_val(val, &str);
        if (!str)
            continue;

        if (mb2_handle_send_file(mobilebackup2, backup_dir, str, &errplist) < 0) {
            free(str);
            //printf("Error when sending file '%s' to device\n", str);
            // TODO: perhaps we can continue, we've got a multi status response?!
            break;
        }
        free(str);
    }

    /* send terminating 0 dword */
    uint32_t zero = 0;
    mobilebackup2_send_raw(mobilebackup2, (char*)&zero, 4, &sent);

    if (!errplist) {
        plist_t emptydict = plist_new_dict();
        mobilebackup2_send_status_response(mobilebackup2, 0, NULL, emptydict);
        plist_free(emptydict);
    } else {
        mobilebackup2_send_status_response(mobilebackup2, -13, "Multi status", errplist);
        plist_free(errplist);
    }
}

static int mb2_receive_filename(mobilebackup2_client_t mobilebackup2, char** filename, backupState *bstate){
    uint32_t nlen = 0;
    uint32_t rlen = 0;

    do {
        nlen = 0;
        rlen = 0;
        mobilebackup2_receive_raw(mobilebackup2, (char*)&nlen, 4, &rlen);
        nlen = ntohl(nlen);

        if ((nlen == 0) && (rlen == 4)) {
            // a zero length means no more files to receive
            return 0;
        } else if(rlen == 0) {
            // device needs more time, waiting...
            continue;
        } else if (nlen > 4096) {
            // filename length is too large
            printf("ERROR: %s: too large filename length (%d)!\n", __func__, nlen);
            return 0;
        }

        if (*filename != NULL) {
            free(*filename);
            *filename = NULL;
        }

        *filename = (char*)malloc(nlen+1);

        rlen = 0;
        mobilebackup2_receive_raw(mobilebackup2, *filename, nlen, &rlen);
        if (rlen != nlen) {
            printf("ERROR: %s: could not read filename\n", __func__);
            return 0;
        }

        char* p = *filename;
        p[rlen] = 0;

        break;
    } while(1 && !bstate->quit_flag);

    return nlen;
}

static int mb2_handle_receive_files(mobilebackup2_client_t mobilebackup2, plist_t message, const char *backup_dir, backupState *bstate)
{
    uint64_t backup_real_size = 0;
    uint64_t backup_total_size = 0;
    uint32_t blocksize;
    uint32_t bdone;
    uint32_t rlen;
    uint32_t nlen = 0;
    uint32_t r;
    char buf[32768];
    char *fname = NULL;
    char *dname = NULL;
    char *bname = NULL;
    char code = 0;
    char last_code = 0;
    plist_t node = NULL;
    FILE *f = NULL;
    unsigned int file_count = 0;
    int errcode = 0;
    char *errdesc = NULL;

    if (!message || (plist_get_node_type(message) != PLIST_ARRAY) || plist_array_get_size(message) < 4 || !backup_dir) return 0;

    node = plist_array_get_item(message, 3);
    if (plist_get_node_type(node) == PLIST_UINT) {
        plist_get_uint_val(node, &backup_total_size);
    }
    if (backup_total_size > 0) {
        PRINT_VERBOSE(1, "Receiving files\n");
    }

    do {
        if (bstate->quit_flag)
            break;

        nlen = mb2_receive_filename(mobilebackup2, &dname, bstate);
        if (nlen == 0) {
            break;
        }

        nlen = mb2_receive_filename(mobilebackup2, &fname, bstate);
        if (!nlen) {
            break;
        }

        if (bname != NULL) {
            free(bname);
            bname = NULL;
        }

        bname = string_build_path(backup_dir, fname, NULL);

        if (fname != NULL) {
            free(fname);
            fname = NULL;
        }

        r = 0;
        nlen = 0;
        mobilebackup2_receive_raw(mobilebackup2, (char*)&nlen, 4, &r);
        if (r != 4) {
            printf("ERROR: %s: could not receive code length!\n", __func__);
            break;
        }
        nlen = ntohl(nlen);

        last_code = code;
        code = 0;

        mobilebackup2_receive_raw(mobilebackup2, &code, 1, &r);
        if (r != 1) {
            printf("ERROR: %s: could not receive code!\n", __func__);
            break;
        }

        /* TODO remove this */
        if ((code != CODE_SUCCESS) && (code != CODE_FILE_DATA) && (code != CODE_ERROR_REMOTE)) {
            PRINT_VERBOSE(1, "Found new flag %02x\n", code);
        }

        remove_file(bname);
        f = fopen(bname, "wb");
        while (f && (code == CODE_FILE_DATA)) {
            blocksize = nlen-1;
            bdone = 0;
            rlen = 0;
            while (bdone < blocksize) {
                if ((blocksize - bdone) < sizeof(buf)) {
                    rlen = blocksize - bdone;
                } else {
                    rlen = sizeof(buf);
                }
                mobilebackup2_receive_raw(mobilebackup2, buf, rlen, &r);
                if ((int)r <= 0) {
                    break;
                }
                fwrite(buf, 1, r, f);
                bdone += r;
            }
            if (bdone == blocksize) {
                backup_real_size += blocksize;
            }
            if (backup_total_size > 0) {
                double progress = (((double)backup_real_size)/backup_total_size) * 100;
                if (bstate->callback) retcustomassure(IBKPexceptionUser_callback_aborted, bstate->callback("progress_local",progress), "User callback aborted");
//                print_progress(backup_real_size, backup_total_size);
            }
            if (bstate->quit_flag)
                break;
            nlen = 0;
            mobilebackup2_receive_raw(mobilebackup2, (char*)&nlen, 4, &r);
            nlen = ntohl(nlen);
            if (nlen > 0) {
                last_code = code;
                mobilebackup2_receive_raw(mobilebackup2, &code, 1, &r);
            } else {
                break;
            }
        }
        if (f) {
            fclose(f);
            file_count++;
        } else {
            errcode = errno_to_device_error(errno);
            errdesc = strerror(errno);
            printf("Error opening '%s' for writing: %s\n", bname, errdesc);
            break;
        }
        if (nlen == 0) {
            break;
        }

        /* check if an error message was received */
        if (code == CODE_ERROR_REMOTE) {
            /* error message */
            char *msg = (char*)malloc(nlen);
            mobilebackup2_receive_raw(mobilebackup2, msg, nlen-1, &r);
            msg[r] = 0;
            /* If sent using CODE_FILE_DATA, end marker will be CODE_ERROR_REMOTE which is not an error! */
            if (last_code != CODE_FILE_DATA) {
                fprintf(stdout, "\nReceived an error message from device: %s\n", msg);
            }
            free(msg);
        }
    } while (1);

    if (fname != NULL)
        free(fname);

    /* if there are leftovers to read, finish up cleanly */
    if ((int)nlen-1 > 0) {
        PRINT_VERBOSE(1, "\nDiscarding current data hunk.\n");
        fname = (char*)malloc(nlen-1);
        mobilebackup2_receive_raw(mobilebackup2, fname, nlen-1, &r);
        free(fname);
        remove_file(bname);
    }

    /* clean up */
    if (bname != NULL)
        free(bname);

    if (dname != NULL)
        free(dname);

    plist_t empty_plist = plist_new_dict();
    mobilebackup2_send_status_response(mobilebackup2, errcode, errdesc, empty_plist);
    plist_free(empty_plist);

    return file_count;
}

static void mb2_handle_list_directory(mobilebackup2_client_t mobilebackup2, plist_t message, const char *backup_dir)
{
    if (!message || (plist_get_node_type(message) != PLIST_ARRAY) || plist_array_get_size(message) < 2 || !backup_dir) return;

    plist_t node = plist_array_get_item(message, 1);
    char *str = NULL;
    if (plist_get_node_type(node) == PLIST_STRING) {
        plist_get_string_val(node, &str);
    }
    if (!str) {
        printf("ERROR: Malformed DLContentsOfDirectory message\n");
        // TODO error handling
        return;
    }

    char *path = string_build_path(backup_dir, str, NULL);
    free(str);

    plist_t dirlist = plist_new_dict();

    DIR* cur_dir = opendir(path);
    if (cur_dir) {
        struct dirent* ep;
        while ((ep = readdir(cur_dir))) {
            if ((strcmp(ep->d_name, ".") == 0) || (strcmp(ep->d_name, "..") == 0)) {
                continue;
            }
            char *fpath = string_build_path(path, ep->d_name, NULL);
            if (fpath) {
                plist_t fdict = plist_new_dict();
                struct stat st;
                stat(fpath, &st);
                const char *ftype = "DLFileTypeUnknown";
                if (S_ISDIR(st.st_mode)) {
                    ftype = "DLFileTypeDirectory";
                } else if (S_ISREG(st.st_mode)) {
                    ftype = "DLFileTypeRegular";
                }
                plist_dict_set_item(fdict, "DLFileType", plist_new_string(ftype));
                plist_dict_set_item(fdict, "DLFileSize", plist_new_uint(st.st_size));
                plist_dict_set_item(fdict, "DLFileModificationDate",
                            plist_new_date((int32_t)(st.st_mtime - MAC_EPOCH), 0));

                plist_dict_set_item(dirlist, ep->d_name, fdict);
                free(fpath);
            }
        }
        closedir(cur_dir);
    }
    free(path);

    /* TODO error handling */
    mobilebackup2_error_t err = mobilebackup2_send_status_response(mobilebackup2, 0, NULL, dirlist);
    plist_free(dirlist);
    if (err != MOBILEBACKUP2_E_SUCCESS) {
        printf("Could not send status response, error %d\n", err);
    }
}

static void mb2_handle_make_directory(mobilebackup2_client_t mobilebackup2, plist_t message, const char *backup_dir)
{
    if (!message || (plist_get_node_type(message) != PLIST_ARRAY) || plist_array_get_size(message) < 2 || !backup_dir) return;

    plist_t dir = plist_array_get_item(message, 1);
    char *str = NULL;
    int errcode = 0;
    char *errdesc = NULL;
    plist_get_string_val(dir, &str);

    char *newpath = string_build_path(backup_dir, str, NULL);
    free(str);

    if (mkdir_with_parents(newpath, 0755) < 0) {
        errdesc = strerror(errno);
        if (errno != EEXIST) {
            printf("mkdir: %s (%d)\n", errdesc, errno);
        }
        errcode = errno_to_device_error(errno);
    }
    free(newpath);
    mobilebackup2_error_t err = mobilebackup2_send_status_response(mobilebackup2, errcode, errdesc, NULL);
    if (err != MOBILEBACKUP2_E_SUCCESS) {
        printf("Could not send status response, error %d\n", err);
    }
}

static void mb2_copy_file_by_path(const char *src, const char *dst)
{
    FILE *from, *to;
    char buf[BUFSIZ];
    size_t length;

    /* open source file */
    if ((from = fopen(src, "rb")) == NULL) {
        printf("Cannot open source path '%s'.\n", src);
        return;
    }

    /* open destination file */
    if ((to = fopen(dst, "wb")) == NULL) {
        printf("Cannot open destination file '%s'.\n", dst);
        fclose(from);
        return;
    }

    /* copy the file */
    while ((length = fread(buf, 1, BUFSIZ, from)) != 0) {
        fwrite(buf, 1, length, to);
    }

    if(fclose(from) == EOF) {
        printf("Error closing source file.\n");
    }

    if(fclose(to) == EOF) {
        printf("Error closing destination file.\n");
    }
}

static void mb2_copy_directory_by_path(const char *src, const char *dst)
{
    if (!src || !dst) {
        return;
    }

    struct stat st;

    /* if src does not exist */
    if ((stat(src, &st) < 0) || !S_ISDIR(st.st_mode)) {
        printf("ERROR: Source directory does not exist '%s': %s (%d)\n", src, strerror(errno), errno);
        return;
    }

    /* if dst directory does not exist */
    if ((stat(dst, &st) < 0) || !S_ISDIR(st.st_mode)) {
        /* create it */
        if (mkdir_with_parents(dst, 0755) < 0) {
            printf("ERROR: Unable to create destination directory '%s': %s (%d)\n", dst, strerror(errno), errno);
            return;
        }
    }

    /* loop over src directory contents */
    DIR *cur_dir = opendir(src);
    if (cur_dir) {
        struct dirent* ep;
        while ((ep = readdir(cur_dir))) {
            if ((strcmp(ep->d_name, ".") == 0) || (strcmp(ep->d_name, "..") == 0)) {
                continue;
            }
            char *srcpath = string_build_path(src, ep->d_name, NULL);
            char *dstpath = string_build_path(dst, ep->d_name, NULL);
            if (srcpath && dstpath) {
                /* copy file */
                mb2_copy_file_by_path(srcpath, dstpath);
            }

            if (srcpath)
                free(srcpath);
            if (dstpath)
                free(dstpath);
        }
        closedir(cur_dir);
    }
}

std::pair<mobilebackup2_error_t, int> backupMessageLoop(mobilebackup2_client_t mobilebackup2, const char *backup_directory, const char *udid, backupState *bstate, bool isBackup = true){
    mobilebackup2_error_t err = MOBILEBACKUP2_E_SUCCESS;
    int result_code = 0;
    int operation_ok = 0;
    mobilebackup2_error_t mberr;
    int file_count = 0;
    int errcode = 0;
    const char *errdesc = NULL;
    int progress_finished = 0;

    /* process series of DLMessage* operations */
    do {
        char *dlmsg = NULL;
        plist_t message = NULL;
        cleanup([&]{
            safeFreeCustom(message, plist_free);
            safeFree(dlmsg);
        });

        mberr = mobilebackup2_receive_message(mobilebackup2, &message, &dlmsg);
        if (mberr == MOBILEBACKUP2_E_RECEIVE_TIMEOUT) {
            debug("Device is not ready yet, retrying...");
            goto files_out;
        } else if (mberr != MOBILEBACKUP2_E_SUCCESS) {
            debug("ERROR: Could not receive from mobilebackup2 (%d)", mberr);
            bstate->quit_flag++;
            goto files_out;
        }

        if (!strcmp(dlmsg, "DLMessageDownloadFiles")) {
            /* device wants to download files from the computer */
            mb2_set_overall_progress_from_message(message, dlmsg, bstate);
            mb2_handle_send_files(mobilebackup2, message, backup_directory);
        } else if (!strcmp(dlmsg, "DLMessageUploadFiles")) {
            /* device wants to send files to the computer */
            mb2_set_overall_progress_from_message(message, dlmsg, bstate);
            file_count += mb2_handle_receive_files(mobilebackup2, message, backup_directory, bstate);
        } else if (!strcmp(dlmsg, "DLMessageGetFreeDiskSpace")) {
            /* device wants to know how much disk space is available on the computer */
            uint64_t freespace = 0;
            int res = -1;
#ifdef WIN32
            if (GetDiskFreeSpaceEx(backup_directory, (PULARGE_INTEGER)&freespace, NULL, NULL)) {
                res = 0;
            }
#else
            struct statvfs fs;
            memset(&fs, '\0', sizeof(fs));
            res = statvfs(backup_directory, &fs);
            if (res == 0) {
                freespace = (uint64_t)fs.f_bavail * (uint64_t)fs.f_bsize;
            }
#endif
            {
                plist_t freespace_item = NULL;
                cleanup([&]{
                    safeFreeCustom(freespace_item, plist_free);
                });
                freespace_item = plist_new_uint(freespace);
                mobilebackup2_send_status_response(mobilebackup2, res, NULL, freespace_item);
            }
        } else if (!strcmp(dlmsg, "DLMessagePurgeDiskSpace")) {
            /* device wants to purge disk space on the host - not supported */
            plist_t empty_dict = NULL;
            cleanup([&]{
                safeFreeCustom(empty_dict, plist_free);
            });
            empty_dict = plist_new_dict();
            err = mobilebackup2_send_status_response(mobilebackup2, -1, "Operation not supported", empty_dict);
        } else if (!strcmp(dlmsg, "DLContentsOfDirectory")) {
            /* list directory contents */
            mb2_handle_list_directory(mobilebackup2, message, backup_directory);
        } else if (!strcmp(dlmsg, "DLMessageCreateDirectory")) {
            /* make a directory */
            mb2_handle_make_directory(mobilebackup2, message, backup_directory);
        } else if (!strcmp(dlmsg, "DLMessageMoveFiles") || !strcmp(dlmsg, "DLMessageMoveItems")) {
            /* perform a series of rename operations */
            
            plist_dict_iter iter = NULL;
            cleanup([&]{
                safeFree(iter);
            });
            
            mb2_set_overall_progress_from_message(message, dlmsg, bstate);
            plist_t moves = plist_array_get_item(message, 1);
            
            uint32_t cnt = plist_dict_get_size(moves);
            debug("Moving %d file%s\n", cnt, (cnt == 1) ? "" : "s");
            
            plist_dict_new_iter(moves, &iter);
            errcode = 0;
            errdesc = NULL;
            if (iter) {
                plist_t val = NULL;
                do {
                    char *key = NULL;
                    cleanup([&]{
                        safeFree(key);
                    });
                    plist_dict_next_item(moves, iter, &key, &val);
                    if (key && (plist_get_node_type(val) == PLIST_STRING)) {
                        char *str = NULL;
                        cleanup([&]{
                            safeFree(str);
                        });
                        plist_get_string_val(val, &str);
                        if (str) {
                            char *newpath = NULL;
                            char *oldpath = NULL;
                            cleanup([&]{
                                safeFree(newpath);
                                safeFree(oldpath);
                            });
                            struct stat st = {};
                            
                            newpath = string_build_path(backup_directory, str, NULL);
                            oldpath = string_build_path(backup_directory, key, NULL);

                            if ((stat(newpath, &st) == 0) && S_ISDIR(st.st_mode))
                                rmdir_recursive(newpath);
                            else
                                remove_file(newpath);
                            if (rename(oldpath, newpath) < 0) {
                                printf("Renameing '%s' to '%s' failed: %s (%d)\n", oldpath, newpath, strerror(errno), errno);
                                errcode = errno_to_device_error(errno);
                                errdesc = strerror(errno);
                                break;
                            }
                        }
                    }
                } while (val);
            } else {
                errcode = -1;
                errdesc = "Could not create dict iterator";
                error("Could not create dict iterator\n");
            }
            
            {
                plist_t empty_dict = NULL;
                cleanup([&]{
                    safeFreeCustom(empty_dict, plist_free);
                });
                empty_dict = plist_new_dict();

                err = mobilebackup2_send_status_response(mobilebackup2, errcode, errdesc, empty_dict);
                if (err != MOBILEBACKUP2_E_SUCCESS) {
                    error("Could not send status response, error %d", err);
                }
            }
        } else if (!strcmp(dlmsg, "DLMessageRemoveFiles") || !strcmp(dlmsg, "DLMessageRemoveItems")) {
            mb2_set_overall_progress_from_message(message, dlmsg, bstate);
            plist_t removes = plist_array_get_item(message, 1);
            uint32_t cnt = plist_array_get_size(removes);
            debug("Removing %d file%s\n", cnt, (cnt == 1) ? "" : "s");
            uint32_t ii = 0;
            errcode = 0;
            errdesc = NULL;
            for (ii = 0; ii < cnt; ii++) {
                plist_t val = plist_array_get_item(removes, ii);
                if (plist_get_node_type(val) == PLIST_STRING) {
                    char *str = NULL;
                    cleanup([&]{
                        safeFree(str);
                    });
                    plist_get_string_val(val, &str);
                    if (str) {
                        const char *checkfile = strchr(str, '/');
                        int suppress_warning = 0;
                        if (checkfile) {
                            if (strcmp(checkfile+1, "Manifest.mbdx") == 0) {
                                suppress_warning = 1;
                            }
                        }
                        char *newpath = NULL;
                        cleanup([&]{
                            safeFree(newpath);
                        });
                        struct stat st = {};
                        newpath = string_build_path(backup_directory, str, NULL);
                        int res = 0;
                        if ((stat(newpath, &st) == 0) && S_ISDIR(st.st_mode)) {
                            res = rmdir_recursive(newpath);
                        } else {
                            res = remove_file(newpath);
                        }
                        if (res != 0 && res != ENOENT) {
                            if (!suppress_warning)
                                error("Could not remove '%s': %s (%d)\n", newpath, strerror(res), res);
                            errcode = errno_to_device_error(res);
                            errdesc = strerror(res);
                        }
                    }
                }
            }
            plist_t empty_dict = NULL;
            cleanup([&]{
                safeFreeCustom(empty_dict, plist_free);
            });
            empty_dict = plist_new_dict();
            err = mobilebackup2_send_status_response(mobilebackup2, errcode, errdesc, empty_dict);
            if (err != MOBILEBACKUP2_E_SUCCESS) {
                error("Could not send status response, error %d\n", err);
            }
        } else if (!strcmp(dlmsg, "DLMessageCopyItem")) {
            plist_t srcpath = plist_array_get_item(message, 1);
            plist_t dstpath = plist_array_get_item(message, 2);
            errcode = 0;
            errdesc = NULL;
            if ((plist_get_node_type(srcpath) == PLIST_STRING) && (plist_get_node_type(dstpath) == PLIST_STRING)) {
                char *src = NULL;
                char *dst = NULL;
                cleanup([&]{
                    safeFree(src);
                    safeFree(dst);
                });
                plist_get_string_val(srcpath, &src);
                plist_get_string_val(dstpath, &dst);
                if (src && dst) {
                    char *oldpath = NULL;
                    char *newpath = NULL;
                    cleanup([&]{
                        safeFree(oldpath);
                        safeFree(newpath);
                    });
                    struct stat st = {};

                    oldpath = string_build_path(backup_directory, src, NULL);
                    newpath = string_build_path(backup_directory, dst, NULL);

                    debug("Copying '%s' to '%s'\n", src, dst);

                    /* check that src exists */
                    if ((stat(oldpath, &st) == 0) && S_ISDIR(st.st_mode)) {
                        mb2_copy_directory_by_path(oldpath, newpath);
                    } else if ((stat(oldpath, &st) == 0) && S_ISREG(st.st_mode)) {
                        mb2_copy_file_by_path(oldpath, newpath);
                    }
                }
            }
            
            plist_t empty_dict = NULL;
            cleanup([&]{
                safeFreeCustom(empty_dict, plist_free);
            });
            empty_dict = plist_new_dict();
            err = mobilebackup2_send_status_response(mobilebackup2, errcode, errdesc, empty_dict);
            if (err != MOBILEBACKUP2_E_SUCCESS) {
                error("Could not send status response, error %d\n", err);
            }
        } else if (!strcmp(dlmsg, "DLMessageDisconnect")) {
            break;
        } else if (!strcmp(dlmsg, "DLMessageProcessMessage")) {
            plist_t node_tmp = NULL;
            node_tmp = plist_array_get_item(message, 1);
            if (plist_get_node_type(node_tmp) != PLIST_DICT) {
                printf("Unknown message received!\n");
            }
            plist_t nn;
            int error_code = -1;
            nn = plist_dict_get_item(node_tmp, "ErrorCode");
            if (nn && (plist_get_node_type(nn) == PLIST_UINT)) {
                uint64_t ec = 0;
                plist_get_uint_val(nn, &ec);
                error_code = (uint32_t)ec;
                if (error_code == 0) {
                    operation_ok = 1;
                    result_code = 0;
                } else {
                    result_code = -error_code;
                }
            }
            nn = plist_dict_get_item(node_tmp, "ErrorDescription");
            char *str = NULL;
            cleanup([&]{
                safeFree(str);
            });
            if (nn && (plist_get_node_type(nn) == PLIST_STRING)) {
                plist_get_string_val(nn, &str);
            }
            if (error_code != 0) {
                if (str) {
                    printf("ErrorCode %d: %s\n", error_code, str);
                } else {
                    printf("ErrorCode %d: (Unknown)\n", error_code);
                }
            }
            nn = plist_dict_get_item(node_tmp, "Content");
            if (nn && (plist_get_node_type(nn) == PLIST_STRING)) {
                char *str = NULL;
                cleanup([&]{
                    safeFree(str);
                });
                plist_get_string_val(nn, &str);
                debug("Content:\n");
                printf("%s", str);
            }
            break;
        }

        /* print status */
        if ((bstate->overall_progress > 0) && !progress_finished) {
            if (bstate->overall_progress >= 100.0f) {
                progress_finished = 1;
            }
            if (bstate->callback) retcustomassure(IBKPexceptionUser_callback_aborted, bstate->callback("progress_global",bstate->overall_progress), "User callback aborted");
//            print_progress_real(bstate->overall_progress, 0);
            debug(" Finished\n");
        }

files_out:
        if (bstate->quit_flag > 0) {
            /* need to cancel the backup here */
            //mobilebackup_send_error(mobilebackup, "Cancelling DLSendFile");

            /* remove any atomic Manifest.plist.tmp */

            /*manifest_path = mobilebackup_build_path(backup_directory, "Manifest", ".plist.tmp");
            if (stat(manifest_path, &st) == 0)
                remove(manifest_path);*/
            break;
        }
    } while (1);
    
    debug("Received %d files from device.\n", file_count);
    if (operation_ok && (!isBackup || mb2_status_check_snapshot_state(backup_directory, udid, "finished"))) {
        if (isBackup) {
            info("Backup Successful.");
        }else{
            info("Success.");
        }
    } else {
        if (bstate->quit_flag) {
            reterror("Backup Aborted.");
        } else {
            reterror("Backup Failed (Error Code %d).", -result_code);
        }
    }
    return {err,result_code};
}
    
void libidevicebackup::doBackup(const char *udid, const char *backup_directory, ProgressCallback callback){
    idevice_t device = NULL;
    char *_udid = NULL;
    char *source_udid = NULL;
    char *info_path = NULL;
    lockdownd_client_t lockdown = NULL;
    lockdownd_service_descriptor_t service = NULL;
    np_client_t np = NULL;
    afc_client_t afc = NULL;
    mobilebackup2_client_t mobilebackup2 = NULL;
    uint64_t lockfile = 0;
    plist_t info_plist = NULL;
    plist_t opts = NULL;
    cleanup([&]{
        safeFreeCustom(opts, plist_free);
        safeFreeCustom(info_plist, plist_free);
        if (lockfile) {
            if (afc) {
                afc_file_close(afc, lockfile); lockfile = 0;
            }
        }
        safeFreeCustom(mobilebackup2, mobilebackup2_client_free);
        safeFreeCustom(afc, afc_client_free);
        safeFreeCustom(np, np_client_free);
        safeFreeCustom(service,lockdownd_service_descriptor_free);
        safeFreeCustom(lockdown, lockdownd_client_free);
        safeFree(info_path);
        safeFree(source_udid);
        safeFree(_udid);
        safeFreeCustom(device, idevice_free);
    });
    idevice_error_t ret = IDEVICE_E_UNKNOWN_ERROR;
    lockdownd_error_t ldret = LOCKDOWN_E_UNKNOWN_ERROR;
    mobilebackup2_error_t err = MOBILEBACKUP2_E_UNKNOWN_ERROR;
    uint8_t willEncrypt = 0;
    int device_version = 0;
    int is_full_backup = 0;
    int result_code = -1;

    backupState bstate = {
        .callback = callback
    };
    
    if (callback) retcustomassure(IBKPexceptionUser_callback_aborted, callback("prepare_device",0), "User callback aborted");
    
    /* verify if passed backup directory exists */
    {
        struct stat st = {};
        retassure(!stat(backup_directory, &st), "Backup directory \"%s\" does not exist!\n",backup_directory);
    }
    
    retassure(!(ret = idevice_new_with_options(&device, udid, IDEVICE_LOOKUP_USBMUX)), "No device found %s%s", (udid ? "with udid " : "."), (udid ? udid : ""));
    
    if (!udid){
        retassure(!(ret = idevice_get_udid(device, &_udid)), "Failed to get udid");
        udid = _udid;
    }

    if (!source_udid) source_udid = strdup(udid);

    assure(info_path = string_build_path(backup_directory, source_udid, "Info.plist", NULL));
    
    retassure(LOCKDOWN_E_SUCCESS == (ldret = lockdownd_client_new_with_handshake(device, &lockdown, TOOL_NAME)), "Could not connect to lockdownd, error code %d", ldret);

    {
        plist_t node_tmp = NULL;
        cleanup([&]{
            safeFreeCustom(node_tmp, plist_free);
        });
        lockdownd_get_value(lockdown, "com.apple.mobile.backup", "WillEncrypt", &node_tmp);
        if (node_tmp) {
            if (plist_get_node_type(node_tmp) == PLIST_BOOLEAN) {
                plist_get_bool_val(node_tmp, &willEncrypt);
            }
        }
    }
    
    /* get ProductVersion */
    {
        char *product_version = NULL;
        plist_t node_tmp = NULL;
        cleanup([&]{
            safeFreeCustom(node_tmp, plist_free);
            safeFree(product_version);
        });
        lockdownd_get_value(lockdown, NULL, "ProductVersion", &node_tmp);
        if (node_tmp) {
            if (plist_get_node_type(node_tmp) == PLIST_STRING) {
                plist_get_string_val(node_tmp, &product_version);
            }
        }
        if (product_version) {
            int vers[3] = { 0, 0, 0 };
            if (sscanf(product_version, "%d.%d.%d", &vers[0], &vers[1], &vers[2]) >= 2) {
                device_version = DEVICE_VERSION(vers[0], vers[1], vers[2]);
            }
        }
    }

    /* start notification_proxy */
    ldret = lockdownd_start_service(lockdown, NP_SERVICE_NAME, &service);
    if ((ldret == LOCKDOWN_E_SUCCESS) && service && service->port) {
        np_client_new(device, service, &np);
        np_set_notify_callback(np, notify_cb, &bstate.quit_flag);
        const char *noties[5] = {
            NP_SYNC_CANCEL_REQUEST,
            NP_SYNC_SUSPEND_REQUEST,
            NP_SYNC_RESUME_REQUEST,
            NP_BACKUP_DOMAIN_CHANGED,
            NULL
        };
        np_observe_notifications(np, noties);
    } else {
        retcustomerror(IBKPexceptionUser_failed_to_start_backup,"Could not start service %s", NP_SERVICE_NAME);
    }
    
    /* start AFC, we need this for the lock file */
    service->port = 0;
    service->ssl_enabled = 0;
    ldret = lockdownd_start_service(lockdown, AFC_SERVICE_NAME, &service);
    if ((ldret == LOCKDOWN_E_SUCCESS) && service->port) {
        afc_client_new(device, service, &afc);
    }
    
    /* start mobilebackup service and retrieve port */
    ldret = lockdownd_start_service_with_escrow_bag(lockdown, MOBILEBACKUP2_SERVICE_NAME, &service);
    retcustomassure(IBKPexceptionUser_failed_to_start_backup, (ldret == LOCKDOWN_E_SUCCESS) && service && service->port, "Could not start service %s", MOBILEBACKUP2_SERVICE_NAME);

    retcustomassure(IBKPexceptionUser_failed_to_start_backup, !mobilebackup2_client_new(device, service, &mobilebackup2), "Failed to start mb2 client");

    /* send Hello message */
    {
        double local_versions[2] = {2.0, 2.1};
        double remote_version = 0.0;
        retcustomassure(IBKPexceptionUser_failed_to_start_backup, !(err = mobilebackup2_version_exchange(mobilebackup2, local_versions, 2, &remote_version)), "Could not perform backup protocol version exchange, error code %d", err);
        debug("Negotiated Protocol Version %.1f", remote_version);
    }

    {
        struct stat st = {};
        if (info_path && (stat(info_path, &st) == 0)) {
            debug("Reading Info.plist from backup.");
            plist_read_from_file(info_path, &info_plist, NULL);
            if (!info_plist) {
                info("Could not read Info.plist\n");
                is_full_backup = 1;
            }
        } else {
            is_full_backup = 1;
        }
    }
    do_post_notification(device, NP_SYNC_WILL_START);
    afc_file_open(afc, "/com.apple.itunes.lock_sync", AFC_FOPEN_RW, &lockfile);
    
    if (lockfile) {
        afc_error_t aerr = {};
        do_post_notification(device, NP_SYNC_LOCK_REQUEST);
        int i = 0;
        for (i = 0; i < LOCK_ATTEMPTS; i++) {
            aerr = afc_file_lock(afc, lockfile, AFC_LOCK_EX);
            if (aerr == AFC_E_SUCCESS) {
                do_post_notification(device, NP_SYNC_DID_START);
                break;
            } else if (aerr == AFC_E_OP_WOULD_BLOCK) {
                usleep(LOCK_WAIT);
                continue;
            } else {
                reterror("could not lock file! error code: %d", aerr);
            }
        }
        retassure(i < LOCK_ATTEMPTS, "timeout while locking for sync");
    }
    
    if (callback) retcustomassure(IBKPexceptionUser_callback_aborted, callback("backup_init",0), "User callback aborted");

    {
        debug("Starting backup...\n");
        /* make sure backup device sub-directory exists */
        {
            char* devbackupdir = NULL;
            cleanup([&]{
                safeFree(devbackupdir);
            });
            assure(devbackupdir = string_build_path(backup_directory, source_udid, NULL));
            __mkdir(devbackupdir, 0755);
        }

        if (strcmp(source_udid, udid) != 0) {
            /* handle different source backup directory */
            // make sure target backup device sub-directory exists
            char* devbackupdir = NULL;
            cleanup([&]{
                safeFree(devbackupdir);
            });
            devbackupdir = string_build_path(backup_directory, udid, NULL);
            __mkdir(devbackupdir, 0755);

            // use Info.plist path in target backup folder */
            safeFree(info_path);
            info_path = string_build_path(backup_directory, udid, "Info.plist", NULL);
        }

        /* TODO: check domain com.apple.mobile.backup key RequiresEncrypt and WillEncrypt with lockdown */
        /* TODO: verify battery on AC enough battery remaining */

        /* re-create Info.plist (Device infos, IC-Info.sidb, photos, app_ids, iTunesPrefs) */
        safeFreeCustom(info_plist, plist_free);
        retassure(info_plist = mobilebackup_factory_info_plist_new(udid, device, afc),"Failed to generate Info.plist - aborting");
        remove_file(info_path);
        plist_write_to_file(info_plist, info_path, PLIST_FORMAT_XML, (plist_write_options_t)0);
        safeFree(info_path);

        safeFreeCustom(info_plist, plist_free);

        if (/*cmd_flags & CMD_FLAG_FORCE_FULL_BACKUP */ 1) {
            debug("Enforcing full backup from device.\n");
            opts = plist_new_dict();
            plist_dict_set_item(opts, "ForceFullBackup", plist_new_bool(1));
        }
        /* request backup from device with manifest from last backup */
        if (willEncrypt) {
            debug("Backup will be encrypted.\n");
        } else {
            debug("Backup will be unencrypted.\n");
        }
        debug("Requesting backup from device...\n");
        err = mobilebackup2_send_request(mobilebackup2, "Backup", udid, source_udid, opts);

        safeFreeCustom(opts, plist_free);

        if (err == MOBILEBACKUP2_E_SUCCESS) {
            if (is_full_backup) {
                debug("Full backup mode.\n");
            } else {
                debug("Incremental backup mode.\n");
            }
        } else {
            if (err == MOBILEBACKUP2_E_BAD_VERSION) {
                reterror("Could not start backup process: backup protocol version mismatch!");
            } else if (err == MOBILEBACKUP2_E_REPLY_NOT_OK) {
                reterror("Could not start backup process: device refused to start the backup process.");
            } else {
                reterror("Could not start backup process: unspecified error occurred");
            }
        }
    }
    
    if (callback) retcustomassure(IBKPexceptionUser_callback_aborted, callback("backup_start",0), "User callback aborted");

    auto r = backupMessageLoop(mobilebackup2, backup_directory, udid, &bstate, true);
    err = r.first;
    result_code = r.second;

    do_post_notification(device, NP_SYNC_DID_FINISH);
    if (callback) callback("backup_done",100);
    info("Done backup!");
}

void libidevicebackup::enableBackupEncryption(const char *udid, std::string backupPassword){
    idevice_t device = NULL;
    char *_udid = NULL;
    lockdownd_client_t lockdown = NULL;
    lockdownd_service_descriptor_t service = NULL;
    np_client_t np = NULL;
    afc_client_t afc = NULL;
    mobilebackup2_client_t mobilebackup2 = NULL;
    cleanup([&]{
        safeFreeCustom(mobilebackup2, mobilebackup2_client_free);
        safeFreeCustom(afc, afc_client_free);
        safeFreeCustom(np, np_client_free);
        safeFreeCustom(service,lockdownd_service_descriptor_free);
        safeFreeCustom(lockdown, lockdownd_client_free);
        safeFree(_udid);
        safeFreeCustom(device, idevice_free);
    });
    idevice_error_t ret = IDEVICE_E_UNKNOWN_ERROR;
    lockdownd_error_t ldret = LOCKDOWN_E_UNKNOWN_ERROR;
    mobilebackup2_error_t err = MOBILEBACKUP2_E_UNKNOWN_ERROR;
    uint8_t willEncrypt = 0;
    int device_version = 0;

    backupState bstate = {};

    retassure(!(ret = idevice_new_with_options(&device, udid, IDEVICE_LOOKUP_USBMUX)), "No device found %s%s", (udid ? "with udid " : "."), (udid ? udid : ""));
    
    if (!udid){
        retassure(!(ret = idevice_get_udid(device, &_udid)), "Failed to get udid");
        udid = _udid;
    }
    
    retassure(LOCKDOWN_E_SUCCESS == (ldret = lockdownd_client_new_with_handshake(device, &lockdown, TOOL_NAME)), "Could not connect to lockdownd, error code %d", ldret);

    {
        plist_t node_tmp = NULL;
        cleanup([&]{
            safeFreeCustom(node_tmp, plist_free);
        });
        lockdownd_get_value(lockdown, "com.apple.mobile.backup", "WillEncrypt", &node_tmp);
        if (node_tmp) {
            if (plist_get_node_type(node_tmp) == PLIST_BOOLEAN) {
                plist_get_bool_val(node_tmp, &willEncrypt);
            }
        }
    }
    
    /* get ProductVersion */
    {
        char *product_version = NULL;
        plist_t node_tmp = NULL;
        cleanup([&]{
            safeFreeCustom(node_tmp, plist_free);
            safeFree(product_version);
        });
        lockdownd_get_value(lockdown, NULL, "ProductVersion", &node_tmp);
        if (node_tmp) {
            if (plist_get_node_type(node_tmp) == PLIST_STRING) {
                plist_get_string_val(node_tmp, &product_version);
            }
        }
        if (product_version) {
            int vers[3] = { 0, 0, 0 };
            if (sscanf(product_version, "%d.%d.%d", &vers[0], &vers[1], &vers[2]) >= 2) {
                device_version = DEVICE_VERSION(vers[0], vers[1], vers[2]);
            }
        }
    }
    
    /* start notification_proxy */
    ldret = lockdownd_start_service(lockdown, NP_SERVICE_NAME, &service);
    if ((ldret == LOCKDOWN_E_SUCCESS) && service && service->port) {
        np_client_new(device, service, &np);
        np_set_notify_callback(np, notify_cb, &bstate.quit_flag);
        const char *noties[5] = {
            NP_SYNC_CANCEL_REQUEST,
            NP_SYNC_SUSPEND_REQUEST,
            NP_SYNC_RESUME_REQUEST,
            NP_BACKUP_DOMAIN_CHANGED,
            NULL
        };
        np_observe_notifications(np, noties);
    } else {
        reterror("Could not start service %s", NP_SERVICE_NAME);
    }
    
    /* start AFC, we need this for the lock file */
    service->port = 0;
    service->ssl_enabled = 0;
    ldret = lockdownd_start_service(lockdown, AFC_SERVICE_NAME, &service);
    if ((ldret == LOCKDOWN_E_SUCCESS) && service->port) {
        afc_client_new(device, service, &afc);
    }
    
    /* start mobilebackup service and retrieve port */
    ldret = lockdownd_start_service_with_escrow_bag(lockdown, MOBILEBACKUP2_SERVICE_NAME, &service);
    retassure((ldret == LOCKDOWN_E_SUCCESS) && service && service->port, "Could not start service %s", MOBILEBACKUP2_SERVICE_NAME);

    retassure(!mobilebackup2_client_new(device, service, &mobilebackup2), "Failed to start mb2 client");

    /* send Hello message */
    {
        double local_versions[2] = {2.0, 2.1};
        double remote_version = 0.0;
        retassure(!(err = mobilebackup2_version_exchange(mobilebackup2, local_versions, 2, &remote_version)), "Could not perform backup protocol version exchange, error code %d", err);
        debug("Negotiated Protocol Version %.1f", remote_version);
    }

    retassure(!willEncrypt, "Backup encryption is already enabled. Aborting.");
    
    {
        plist_t opts = NULL;
        cleanup([&]{
            safeFreeCustom(opts, plist_free);
        });
        opts = plist_new_dict();
        plist_dict_set_item(opts, "TargetIdentifier", plist_new_string(udid));
        
        plist_dict_set_item(opts, "NewPassword", plist_new_string(backupPassword.c_str()));

        mobilebackup2_send_message(mobilebackup2, "ChangePassword", opts);
        uint8_t passcode_hint = 0;
        if (device_version >= DEVICE_VERSION(13,0,0)) {
            diagnostics_relay_client_t diag = NULL;
            cleanup([&]{
                if (diag) {
                    diagnostics_relay_goodbye(diag);
                }
                safeFreeCustom(diag, diagnostics_relay_client_free);
            });
            if (diagnostics_relay_client_start_service(device, &diag, TOOL_NAME) == DIAGNOSTICS_RELAY_E_SUCCESS) {
                plist_t dict = NULL;
                plist_t keys = NULL;
                cleanup([&]{
                    safeFreeCustom(keys, plist_free);
                    safeFreeCustom(dict, plist_free);
                });
                keys = plist_new_array();
                plist_array_append_item(keys, plist_new_string("PasswordConfigured"));
                if (diagnostics_relay_query_mobilegestalt(diag, keys, &dict) == DIAGNOSTICS_RELAY_E_SUCCESS) {
                    plist_t node = plist_access_path(dict, 2, "MobileGestalt", "PasswordConfigured");
                    plist_get_bool_val(node, &passcode_hint);
                }
            }
        }
        if (passcode_hint) {
            info("Please confirm enabling the backup encryption by entering the passcode on the device.\n");
        }
    }
    
    auto r = backupMessageLoop(mobilebackup2, "/.THIS_DIRECTORY_DOES_NOT_EXIST_ON_PURPOSE__/", udid, &bstate, false);
    retassure((r.first | r.second) == 0, "Failed to set backup password");
    info("Set backup password!");
}

void libidevicebackup::disableBackupEncryption(const char *udid, std::string backupPassword){
    idevice_t device = NULL;
    char *_udid = NULL;
    lockdownd_client_t lockdown = NULL;
    lockdownd_service_descriptor_t service = NULL;
    np_client_t np = NULL;
    afc_client_t afc = NULL;
    mobilebackup2_client_t mobilebackup2 = NULL;
    cleanup([&]{
        safeFreeCustom(mobilebackup2, mobilebackup2_client_free);
        safeFreeCustom(afc, afc_client_free);
        safeFreeCustom(np, np_client_free);
        safeFreeCustom(service,lockdownd_service_descriptor_free);
        safeFreeCustom(lockdown, lockdownd_client_free);
        safeFree(_udid);
        safeFreeCustom(device, idevice_free);
    });
    idevice_error_t ret = IDEVICE_E_UNKNOWN_ERROR;
    lockdownd_error_t ldret = LOCKDOWN_E_UNKNOWN_ERROR;
    mobilebackup2_error_t err = MOBILEBACKUP2_E_UNKNOWN_ERROR;
    uint8_t willEncrypt = 0;
    int device_version = 0;

    backupState bstate = {};

    retassure(!(ret = idevice_new_with_options(&device, udid, IDEVICE_LOOKUP_USBMUX)), "No device found %s%s", (udid ? "with udid " : "."), (udid ? udid : ""));
    
    if (!udid){
        retassure(!(ret = idevice_get_udid(device, &_udid)), "Failed to get udid");
        udid = _udid;
    }
    
    retassure(LOCKDOWN_E_SUCCESS == (ldret = lockdownd_client_new_with_handshake(device, &lockdown, TOOL_NAME)), "Could not connect to lockdownd, error code %d", ldret);

    {
        plist_t node_tmp = NULL;
        cleanup([&]{
            safeFreeCustom(node_tmp, plist_free);
        });
        lockdownd_get_value(lockdown, "com.apple.mobile.backup", "WillEncrypt", &node_tmp);
        if (node_tmp) {
            if (plist_get_node_type(node_tmp) == PLIST_BOOLEAN) {
                plist_get_bool_val(node_tmp, &willEncrypt);
            }
        }
    }
    
    /* get ProductVersion */
    {
        char *product_version = NULL;
        plist_t node_tmp = NULL;
        cleanup([&]{
            safeFreeCustom(node_tmp, plist_free);
            safeFree(product_version);
        });
        lockdownd_get_value(lockdown, NULL, "ProductVersion", &node_tmp);
        if (node_tmp) {
            if (plist_get_node_type(node_tmp) == PLIST_STRING) {
                plist_get_string_val(node_tmp, &product_version);
            }
        }
        if (product_version) {
            int vers[3] = { 0, 0, 0 };
            if (sscanf(product_version, "%d.%d.%d", &vers[0], &vers[1], &vers[2]) >= 2) {
                device_version = DEVICE_VERSION(vers[0], vers[1], vers[2]);
            }
        }
    }
    
    /* start notification_proxy */
    ldret = lockdownd_start_service(lockdown, NP_SERVICE_NAME, &service);
    if ((ldret == LOCKDOWN_E_SUCCESS) && service && service->port) {
        np_client_new(device, service, &np);
        np_set_notify_callback(np, notify_cb, &bstate.quit_flag);
        const char *noties[5] = {
            NP_SYNC_CANCEL_REQUEST,
            NP_SYNC_SUSPEND_REQUEST,
            NP_SYNC_RESUME_REQUEST,
            NP_BACKUP_DOMAIN_CHANGED,
            NULL
        };
        np_observe_notifications(np, noties);
    } else {
        reterror("Could not start service %s", NP_SERVICE_NAME);
    }
    
    /* start AFC, we need this for the lock file */
    service->port = 0;
    service->ssl_enabled = 0;
    ldret = lockdownd_start_service(lockdown, AFC_SERVICE_NAME, &service);
    if ((ldret == LOCKDOWN_E_SUCCESS) && service->port) {
        afc_client_new(device, service, &afc);
    }
    
    /* start mobilebackup service and retrieve port */
    ldret = lockdownd_start_service_with_escrow_bag(lockdown, MOBILEBACKUP2_SERVICE_NAME, &service);
    retassure((ldret == LOCKDOWN_E_SUCCESS) && service && service->port, "Could not start service %s", MOBILEBACKUP2_SERVICE_NAME);

    retassure(!mobilebackup2_client_new(device, service, &mobilebackup2), "Failed to start mb2 client");

    /* send Hello message */
    {
        double local_versions[2] = {2.0, 2.1};
        double remote_version = 0.0;
        retassure(!(err = mobilebackup2_version_exchange(mobilebackup2, local_versions, 2, &remote_version)), "Could not perform backup protocol version exchange, error code %d", err);
        debug("Negotiated Protocol Version %.1f", remote_version);
    }

    retassure(willEncrypt, "Backup encryption is already disabled. Aborting.");
    
    {
        plist_t opts = NULL;
        cleanup([&]{
            safeFreeCustom(opts, plist_free);
        });
        opts = plist_new_dict();
        plist_dict_set_item(opts, "TargetIdentifier", plist_new_string(udid));
        
        plist_dict_set_item(opts, "OldPassword", plist_new_string(backupPassword.c_str()));

        mobilebackup2_send_message(mobilebackup2, "ChangePassword", opts);
        uint8_t passcode_hint = 0;
        if (device_version >= DEVICE_VERSION(13,0,0)) {
            diagnostics_relay_client_t diag = NULL;
            cleanup([&]{
                if (diag) {
                    diagnostics_relay_goodbye(diag);
                }
                safeFreeCustom(diag, diagnostics_relay_client_free);
            });
            if (diagnostics_relay_client_start_service(device, &diag, TOOL_NAME) == DIAGNOSTICS_RELAY_E_SUCCESS) {
                plist_t dict = NULL;
                plist_t keys = NULL;
                cleanup([&]{
                    safeFreeCustom(keys, plist_free);
                    safeFreeCustom(dict, plist_free);
                });
                keys = plist_new_array();
                plist_array_append_item(keys, plist_new_string("PasswordConfigured"));
                if (diagnostics_relay_query_mobilegestalt(diag, keys, &dict) == DIAGNOSTICS_RELAY_E_SUCCESS) {
                    plist_t node = plist_access_path(dict, 2, "MobileGestalt", "PasswordConfigured");
                    plist_get_bool_val(node, &passcode_hint);
                }
            }
        }
        if (passcode_hint) {
            info("Please confirm enabling the backup encryption by entering the passcode on the device.\n");
        }
    }
    
    auto r = backupMessageLoop(mobilebackup2, NULL, udid, &bstate, false);
    retassure((r.first | r.second) == 0, "Failed to unset backup password");
    info("Unset backup password!");
}

void libidevicebackup::changeBackupEncryptionPassword(const char *udid, std::string oldPassword, std::string newPassword){
    idevice_t device = NULL;
    char *_udid = NULL;
    lockdownd_client_t lockdown = NULL;
    lockdownd_service_descriptor_t service = NULL;
    np_client_t np = NULL;
    afc_client_t afc = NULL;
    mobilebackup2_client_t mobilebackup2 = NULL;
    cleanup([&]{
        safeFreeCustom(mobilebackup2, mobilebackup2_client_free);
        safeFreeCustom(afc, afc_client_free);
        safeFreeCustom(np, np_client_free);
        safeFreeCustom(service,lockdownd_service_descriptor_free);
        safeFreeCustom(lockdown, lockdownd_client_free);
        safeFree(_udid);
        safeFreeCustom(device, idevice_free);
    });
    idevice_error_t ret = IDEVICE_E_UNKNOWN_ERROR;
    lockdownd_error_t ldret = LOCKDOWN_E_UNKNOWN_ERROR;
    mobilebackup2_error_t err = MOBILEBACKUP2_E_UNKNOWN_ERROR;
    uint8_t willEncrypt = 0;
    int device_version = 0;

    backupState bstate = {};

    retassure(!(ret = idevice_new_with_options(&device, udid, IDEVICE_LOOKUP_USBMUX)), "No device found %s%s", (udid ? "with udid " : "."), (udid ? udid : ""));
    
    if (!udid){
        retassure(!(ret = idevice_get_udid(device, &_udid)), "Failed to get udid");
        udid = _udid;
    }
    
    retassure(LOCKDOWN_E_SUCCESS == (ldret = lockdownd_client_new_with_handshake(device, &lockdown, TOOL_NAME)), "Could not connect to lockdownd, error code %d", ldret);

    {
        plist_t node_tmp = NULL;
        cleanup([&]{
            safeFreeCustom(node_tmp, plist_free);
        });
        lockdownd_get_value(lockdown, "com.apple.mobile.backup", "WillEncrypt", &node_tmp);
        if (node_tmp) {
            if (plist_get_node_type(node_tmp) == PLIST_BOOLEAN) {
                plist_get_bool_val(node_tmp, &willEncrypt);
            }
        }
    }
    
    /* get ProductVersion */
    {
        char *product_version = NULL;
        plist_t node_tmp = NULL;
        cleanup([&]{
            safeFreeCustom(node_tmp, plist_free);
            safeFree(product_version);
        });
        lockdownd_get_value(lockdown, NULL, "ProductVersion", &node_tmp);
        if (node_tmp) {
            if (plist_get_node_type(node_tmp) == PLIST_STRING) {
                plist_get_string_val(node_tmp, &product_version);
            }
        }
        if (product_version) {
            int vers[3] = { 0, 0, 0 };
            if (sscanf(product_version, "%d.%d.%d", &vers[0], &vers[1], &vers[2]) >= 2) {
                device_version = DEVICE_VERSION(vers[0], vers[1], vers[2]);
            }
        }
    }
    
    /* start notification_proxy */
    ldret = lockdownd_start_service(lockdown, NP_SERVICE_NAME, &service);
    if ((ldret == LOCKDOWN_E_SUCCESS) && service && service->port) {
        np_client_new(device, service, &np);
        np_set_notify_callback(np, notify_cb, &bstate.quit_flag);
        const char *noties[5] = {
            NP_SYNC_CANCEL_REQUEST,
            NP_SYNC_SUSPEND_REQUEST,
            NP_SYNC_RESUME_REQUEST,
            NP_BACKUP_DOMAIN_CHANGED,
            NULL
        };
        np_observe_notifications(np, noties);
    } else {
        reterror("Could not start service %s", NP_SERVICE_NAME);
    }
    
    /* start AFC, we need this for the lock file */
    service->port = 0;
    service->ssl_enabled = 0;
    ldret = lockdownd_start_service(lockdown, AFC_SERVICE_NAME, &service);
    if ((ldret == LOCKDOWN_E_SUCCESS) && service->port) {
        afc_client_new(device, service, &afc);
    }
    
    /* start mobilebackup service and retrieve port */
    ldret = lockdownd_start_service_with_escrow_bag(lockdown, MOBILEBACKUP2_SERVICE_NAME, &service);
    retassure((ldret == LOCKDOWN_E_SUCCESS) && service && service->port, "Could not start service %s", MOBILEBACKUP2_SERVICE_NAME);

    retassure(!mobilebackup2_client_new(device, service, &mobilebackup2), "Failed to start mb2 client");

    /* send Hello message */
    {
        double local_versions[2] = {2.0, 2.1};
        double remote_version = 0.0;
        retassure(!(err = mobilebackup2_version_exchange(mobilebackup2, local_versions, 2, &remote_version)), "Could not perform backup protocol version exchange, error code %d", err);
        debug("Negotiated Protocol Version %.1f", remote_version);
    }

    retassure(willEncrypt, "Backup encryption is already disabled. Aborting.");
    
    {
        plist_t opts = NULL;
        cleanup([&]{
            safeFreeCustom(opts, plist_free);
        });
        opts = plist_new_dict();
        plist_dict_set_item(opts, "TargetIdentifier", plist_new_string(udid));
        
        plist_dict_set_item(opts, "OldPassword", plist_new_string(oldPassword.c_str()));
        plist_dict_set_item(opts, "NewPassword", plist_new_string(newPassword.c_str()));

        mobilebackup2_send_message(mobilebackup2, "ChangePassword", opts);
        uint8_t passcode_hint = 0;
        if (device_version >= DEVICE_VERSION(13,0,0)) {
            diagnostics_relay_client_t diag = NULL;
            cleanup([&]{
                if (diag) {
                    diagnostics_relay_goodbye(diag);
                }
                safeFreeCustom(diag, diagnostics_relay_client_free);
            });
            if (diagnostics_relay_client_start_service(device, &diag, TOOL_NAME) == DIAGNOSTICS_RELAY_E_SUCCESS) {
                plist_t dict = NULL;
                plist_t keys = NULL;
                cleanup([&]{
                    safeFreeCustom(keys, plist_free);
                    safeFreeCustom(dict, plist_free);
                });
                keys = plist_new_array();
                plist_array_append_item(keys, plist_new_string("PasswordConfigured"));
                if (diagnostics_relay_query_mobilegestalt(diag, keys, &dict) == DIAGNOSTICS_RELAY_E_SUCCESS) {
                    plist_t node = plist_access_path(dict, 2, "MobileGestalt", "PasswordConfigured");
                    plist_get_bool_val(node, &passcode_hint);
                }
            }
        }
        if (passcode_hint) {
            info("Please confirm enabling the backup encryption by entering the passcode on the device.\n");
        }
    }
    
    auto r = backupMessageLoop(mobilebackup2, NULL, udid, &bstate, false);
    retassure((r.first | r.second) == 0, "Failed to change backup password");
    info("Changed backup password!");
}

bool libidevicebackup::isBackupPasswordEnabled(const char *udid){
    idevice_t device = NULL;
    lockdownd_client_t lockdown = NULL;
    cleanup([&]{
        safeFreeCustom(lockdown, lockdownd_client_free);
        safeFreeCustom(device, idevice_free);
    });
    idevice_error_t ret = IDEVICE_E_UNKNOWN_ERROR;
    lockdownd_error_t ldret = LOCKDOWN_E_UNKNOWN_ERROR;
    uint8_t willEncrypt = 0;

    retassure(!(ret = idevice_new_with_options(&device, udid, IDEVICE_LOOKUP_USBMUX)), "No device found %s%s", (udid ? "with udid " : "."), (udid ? udid : ""));
        
    retassure(LOCKDOWN_E_SUCCESS == (ldret = lockdownd_client_new_with_handshake(device, &lockdown, TOOL_NAME)), "Could not connect to lockdownd, error code %d", ldret);

    {
        plist_t node_tmp = NULL;
        cleanup([&]{
            safeFreeCustom(node_tmp, plist_free);
        });
        lockdownd_get_value(lockdown, "com.apple.mobile.backup", "WillEncrypt", &node_tmp);
        if (node_tmp) {
            if (plist_get_node_type(node_tmp) == PLIST_BOOLEAN) {
                plist_get_bool_val(node_tmp, &willEncrypt);
            }
        }
    }
    return willEncrypt;
}
