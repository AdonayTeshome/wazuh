/*
 * Dll load notification helper.
 * Copyright (C) 2015, Wazuh Inc.
 * November 16, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "dll_load_notify.h"

#ifdef WIN32
#include <versionhelpers.h>

_LdrRegisterDllNotification LdrRegisterDllNotification = NULL;
_LdrUnregisterDllNotification LdrUnregisterDllNotifcation = NULL;
PVOID cookie_dll_notification = NULL;

/**
 *@brief Verify all the DLLs that are already loaded
 */
static void loaded_modules_verification()
{
#if IMAGE_TRUST_CHECKS != 0
    HMODULE handle_module[OS_SIZE_1024];
    HANDLE handle_process = GetCurrentProcess();
    DWORD handle_bytes_needed = 0;

    if (EnumProcessModules(handle_process,
                           handle_module,
                           sizeof(handle_module), &handle_bytes_needed)) {

        for (size_t i = 0; i < (handle_bytes_needed / sizeof(HMODULE)); i++) {
            wchar_t module_name[MAX_PATH];

            // Get the full path to the module's file.
            if (GetModuleFileNameExW(handle_process,
                                     handle_module[i],
                                     module_name,
                                     sizeof(module_name) / sizeof(wchar_t))) {
                // Check if the images loaded are signed.
                if (verify_hash_and_pe_signature(module_name) != OS_SUCCESS) {
#if IMAGE_TRUST_CHECKS == 2
                    merror_exit("The file '%S' is not signed or its signature is invalid.", module_name);
#else
                    mwarn("The file '%S' is not signed or its signature is invalid.", module_name);
#endif // IMAGE_TRUST_CHECKS == 2
                } else {
                    mdebug1("The file '%S' is signed and its signature is valid.", module_name);
                }
            }
        }
    } else {
#if IMAGE_TRUST_CHECKS == 2
        merror_exit("The mechanism of signature validation for loaded modules at startup failed because the modules"
                    " of the process couldn't be enumerated. Error: %lu", GetLastError());
#else
        mwarn("The mechanism of signature validation for loaded modules at startup failed because the modules of the"
              " process couldn't be enumerated. Error: %lu", GetLastError());
#endif // IMAGE_TRUST_CHECKS == 2

    }
#endif // IMAGE_TRUST_CHECKS != 0
}

/**
 * @brief Callback function for DLL load notifications
 * @param reason Reason for the notification.
 * @param notification_data Data for the notification.
 * @param context Context for the notification.
 */
void CALLBACK dll_notification(ULONG reason,
                               PLDR_DLL_NOTIFICATION_DATA notification_data,
                               __attribute__((unused)) PVOID context)
{
    //Check for the reason
    switch(reason)
    {
    case LDR_DLL_NOTIFICATION_REASON_LOADED:
#if IMAGE_TRUST_CHECKS != 0
        if (verify_hash_and_pe_signature(notification_data->loaded.full_dll_name->Buffer) != OS_SUCCESS) {
#if IMAGE_TRUST_CHECKS == 2
            merror_exit("The file '%S' is not signed or its signature is invalid.",
                        notification_data->loaded.full_dll_name->Buffer);
#else
            mwarn("The file '%S' is not signed or its signature is invalid.",
                  notification_data->loaded.full_dll_name->Buffer);
#endif // IMAGE_TRUST_CHECKS == 2
        } else {
            mdebug1("The file '%S' is signed and its signature is valid.",
                    notification_data->loaded.full_dll_name->Buffer);
        }
#endif // IMAGE_TRUST_CHECKS != 0
        break;
    case LDR_DLL_NOTIFICATION_REASON_UNLOADED:
        mdebug1("Unloaded: '%S'", notification_data->unloaded.full_dll_name->Buffer);
        break;
    }
}

/**
 * @brief Register for DLL load notifications and verify all the DLLs that are already loaded
 */
void enable_dll_verification()
{
#if IMAGE_TRUST_CHECKS != 0
    // Check if all loaded DLLs are signed.
    if (ERROR_SUCCESS != check_ca_available("DigiCert")) {
        merror("The dynamic signature validation is not available because the CA name is not available.");
    } else {
        loaded_modules_verification();

        // Register for DLL load notifications.
        HMODULE handle_ntdll = GetModuleHandle("ntdll.dll");
        if (handle_ntdll) {
            LdrRegisterDllNotification = (_LdrRegisterDllNotification)GetProcAddress(handle_ntdll,
                                                                                    "LdrRegisterDllNotification");
            // If the function is available, the feature is available.
            if (LdrRegisterDllNotification)
            {
                LdrRegisterDllNotification(0, &dll_notification, NULL, &cookie_dll_notification);
            } else {
#if IMAGE_TRUST_CHECKS == 2
                merror_exit("The dynamic signature validation is not available for this system. Error"
                            " %lu: %s", GetLastError(), win_strerror(GetLastError()));
#else
                mwarn("The dynamic signature validation is not available for this system. Error"
                    " %lu: %s", GetLastError(), win_strerror(GetLastError()));
#endif // IMAGE_TRUST_CHECKS == 2
            }
        } else {
#if IMAGE_TRUST_CHECKS == 2
            merror_exit("The mechanism of dynamic signature validation for loaded modules wasn't initiated because it "
                        "wasn't possible to get the handle of 'ntdll.dll'. Error %lu: %s",
                        GetLastError(), win_strerror(GetLastError()));
#else
            mwarn("The mechanism of dynamic signature validation for loaded modules wasn't initiated because it wasn't "
                "possible to get the handle of 'ntdll.dll'. Error %lu: %s",
                GetLastError(), win_strerror(GetLastError()));
#endif // IMAGE_TRUST_CHECKS == 2
        }
    }
#endif // IMAGE_TRUST_CHECKS != 0
}

#endif // WIN32
