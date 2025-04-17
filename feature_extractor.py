##########################################################################################
# File Name   : feature_extractor.py
# Author      : Gautam Kakadiya
# Description : Extracts the Features of Android apks permissions, intents and sensitive api calls
# Created On  : 17-04-2025
# Last Edited : 17-04-2025 by Gautam Kakadiya
# Version     : 1.0.0
# Copyright   : © 2025 Gautam Kakadiya. All rights reserved.
##########################################################################################

import multiprocessing
import sys
import shutil
import subprocess
import xml.etree.ElementTree as ET
import networkx as nx
import re
import os
#test

def extract_manifests(directory):
    os.makedirs("./manifests/", exist_ok=True)
    for filename in os.listdir(directory):
        # Get the full filepath for running the command
        filepath = os.path.join(directory, filename)

        # Check if it is a file (not a directory)
        if os.path.isfile(filepath):
            print(f"Running command on: {filepath}" + f" {filename}")

            # Run the external command on the file
            try:
                # Build up command to unpack APK
                command = ['java', '-jar', './apktool.jar', 'd', '-o', "./apkd/" + filename, filepath]

                # Modify the command to run the process
                result = subprocess.run(command, check=True, capture_output=True, text=True)

                # Optionally, you can handle the command's output here
                print(f"Command output: {result.stdout}")
                output_dir = "./apkd/" + filename
                manifest_path = os.path.join(output_dir, 'AndroidManifest.xml')
                if os.path.isfile(manifest_path):
                    # Define the destination path for the manifest file
                    manifest_dest = os.path.join("./manifests/", f"{filename.replace('.apk', '')}_AndroidManifest.xml")

                    # Copy the manifest file to the manifests directory
                    shutil.copy(manifest_path, manifest_dest)
                    print(f"Copied AndroidManifest.xml to: {manifest_dest}")
                else:
                    print(f"AndroidManifest.xml not found in: {output_dir}")

            except subprocess.CalledProcessError as e:
                print(f"Error running command on {filepath}: {e.stderr}")


def extract_callgraph(directory):
    os.makedirs("./callgraphs/", exist_ok=True)
    for filename in os.listdir(directory):
        # Get the full filepath for running the command
        filepath = os.path.join(directory, filename)

        # Check if it is a file (not a directory)
        if os.path.isfile(filepath):
            print(f"Running extract callgraph command on: {filepath}" + f" {filename}")

            # Run the external command on the file
            try:
                # Build up command to unpack APK
                command = ['androguard', 'cg', filepath]

                # Modify the command to run the process
                result = subprocess.run(command, check=True, capture_output=True, text=True)

                # Optionally, you can handle the command's output here
                print(f"Command output: {result.stdout}")
                callgraph_path = os.path.join("./", 'callgraph.gml')
                if os.path.isfile(callgraph_path):
                    # Define the destination path for the manifest file
                    callgraph_dest = os.path.join("./callgraphs/", f"{filename.replace('.apk', '')}_callgraph.gml")

                    # Copy the manifest file to the manifests directory
                    shutil.copy(callgraph_path, callgraph_dest)
                    print(f"Copied callgraph.cg to: {callgraph_dest}")
                else:
                    print(f"callgraph.cg not found in: {directory}")

            except subprocess.CalledProcessError as e:
                print(f"Error running command on {filepath}: {e.stderr}")



def extract_permissions():
    """
        Parses an AndroidManifest.xml file and returns a dictionary
        indicating the presence of permissions.

        Returns:
            dict: A dictionary where keys are common intent action strings
                  and values are 1 if the action is found in the manifest
                  within an <intent-filter>, and 0 otherwise.
    """
    directory = './manifests/'
    permissions = {
        "ACCEPT_HANDOVER": 0,
        "ACCESS_BACKGROUND_LOCATION": 0,
        "ACCESS_BLOBS_ACROSS_USERS": 0,
        "ACCESS_CHECKIN_PROPERTIES": 0,
        "ACCESS_COARSE_LOCATION": 0,
        "ACCESS_FINE_LOCATION": 0,
        "ACCESS_HIDDEN_PROFILES": 0,
        "ACCESS_LOCATION_EXTRA_COMMANDS": 0,
        "ACCESS_MEDIA_LOCATION": 0,
        "ACCESS_NETWORK_STATE": 0,
        "ACCESS_NOTIFICATION_POLICY": 0,
        "ACCESS_WIFI_STATE": 0,
        "ACCOUNT_MANAGER": 0,
        "ACTIVITY_RECOGNITION": 0,
        "ADD_VOICEMAIL": 0,
        "ANSWER_PHONE_CALLS": 0,
        "APPLY_PICTURE_PROFILE": 0,
        "BATTERY_STATS": 0,
        "BIND_ACCESSIBILITY_SERVICE": 0,
        "BIND_APPWIDGET": 0,
        "BIND_APP_FUNCTION_SERVICE": 0,
        "BIND_AUTOFILL_SERVICE": 0,
        "BIND_CALL_REDIRECTION_SERVICE": 0,
        "BIND_CARRIER_MESSAGING_CLIENT_SERVICE": 0,
        "BIND_CARRIER_MESSAGING_SERVICE": 0,
        "BIND_CARRIER_SERVICES": 0,
        "BIND_CHOOSER_TARGET_SERVICE": 0,
        "BIND_COMPANION_DEVICE_SERVICE": 0,
        "BIND_CONDITION_PROVIDER_SERVICE": 0,
        "BIND_CONTROLS": 0,
        "BIND_CREDENTIAL_PROVIDER_SERVICE": 0,
        "BIND_DEVICE_ADMIN": 0,
        "BIND_DREAM_SERVICE": 0,
        "BIND_INCALL_SERVICE": 0,
        "BIND_INPUT_METHOD": 0,
        "BIND_MIDI_DEVICE_SERVICE": 0,
        "BIND_NFC_SERVICE": 0,
        "BIND_NOTIFICATION_LISTENER_SERVICE": 0,
        "BIND_PRINT_SERVICE": 0,
        "BIND_QUICK_ACCESS_WALLET_SERVICE": 0,
        "BIND_QUICK_SETTINGS_TILE": 0,
        "BIND_REMOTEVIEWS": 0,
        "BIND_SCREENING_SERVICE": 0,
        "BIND_TELECOM_CONNECTION_SERVICE": 0,
        "BIND_TEXT_SERVICE": 0,
        "BIND_TV_AD_SERVICE": 0,
        "BIND_TV_INPUT": 0,
        "BIND_TV_INTERACTIVE_APP": 0,
        "BIND_VISUAL_VOICEMAIL_SERVICE": 0,
        "BIND_VOICE_INTERACTION": 0,
        "BIND_VPN_SERVICE": 0,
        "BIND_VR_LISTENER_SERVICE": 0,
        "BIND_WALLPAPER": 0,
        "BLUETOOTH": 0,
        "BLUETOOTH_ADMIN": 0,
        "BLUETOOTH_ADVERTISE": 0,
        "BLUETOOTH_CONNECT": 0,
        "BLUETOOTH_PRIVILEGED": 0,
        "BLUETOOTH_SCAN": 0,
        "BODY_SENSORS": 0,
        "BODY_SENSORS_BACKGROUND": 0,
        "BROADCAST_PACKAGE_REMOVED": 0,
        "BROADCAST_SMS": 0,
        "BROADCAST_STICKY": 0,
        "BROADCAST_WAP_PUSH": 0,
        "CALL_COMPANION_APP": 0,
        "CALL_PHONE": 0,
        "CALL_PRIVILEGED": 0,
        "CAMERA": 0,
        "CAPTURE_AUDIO_OUTPUT": 0,
        "CHANGE_COMPONENT_ENABLED_STATE": 0,
        "CHANGE_CONFIGURATION": 0,
        "CHANGE_NETWORK_STATE": 0,
        "CHANGE_WIFI_MULTICAST_STATE": 0,
        "CHANGE_WIFI_STATE": 0,
        "CLEAR_APP_CACHE": 0,
        "CONFIGURE_WIFI_DISPLAY": 0,
        "CONTROL_LOCATION_UPDATES": 0,
        "CREDENTIAL_MANAGER_QUERY_CANDIDATE_CREDENTIALS": 0,
        "CREDENTIAL_MANAGER_SET_ALLOWED_PROVIDERS": 0,
        "CREDENTIAL_MANAGER_SET_ORIGIN": 0,
        "DELETE_CACHE_FILES": 0,
        "DELETE_PACKAGES": 0,
        "DELIVER_COMPANION_MESSAGES": 0,
        "DETECT_SCREEN_CAPTURE": 0,
        "DETECT_SCREEN_RECORDING": 0,
        "DIAGNOSTIC": 0,
        "DISABLE_KEYGUARD": 0,
        "DUMP": 0,
        "ENFORCE_UPDATE_OWNERSHIP": 0,
        "EXECUTE_APP_ACTION": 0,
        "EXECUTE_APP_FUNCTIONS": 0,
        "EXPAND_STATUS_BAR": 0,
        "FACTORY_TEST": 0,
        "FOREGROUND_SERVICE": 0,
        "FOREGROUND_SERVICE_CAMERA": 0,
        "FOREGROUND_SERVICE_CONNECTED_DEVICE": 0,
        "FOREGROUND_SERVICE_DATA_SYNC": 0,
        "FOREGROUND_SERVICE_HEALTH": 0,
        "FOREGROUND_SERVICE_LOCATION": 0,
        "FOREGROUND_SERVICE_MEDIA_PLAYBACK": 0,
        "FOREGROUND_SERVICE_MEDIA_PROCESSING": 0,
        "FOREGROUND_SERVICE_MEDIA_PROJECTION": 0,
        "FOREGROUND_SERVICE_MICROPHONE": 0,
        "FOREGROUND_SERVICE_PHONE_CALL": 0,
        "FOREGROUND_SERVICE_REMOTE_MESSAGING": 0,
        "FOREGROUND_SERVICE_SPECIAL_USE": 0,
        "FOREGROUND_SERVICE_SYSTEM_EXEMPTED": 0,
        "GET_ACCOUNTS": 0,
        "GET_ACCOUNTS_PRIVILEGED": 0,
        "GET_PACKAGE_SIZE": 0,
        "GET_TASKS": 0,
        "GLOBAL_SEARCH": 0,
        "HIDE_OVERLAY_WINDOWS": 0,
        "HIGH_SAMPLING_RATE_SENSORS": 0,
        "INSTALL_LOCATION_PROVIDER": 0,
        "INSTALL_PACKAGES": 0,
        "INSTALL_SHORTCUT": 0,
        "INSTANT_APP_FOREGROUND_SERVICE": 0,
        "INTERACT_ACROSS_PROFILES": 0,
        "INTERNET": 0,
        "KILL_BACKGROUND_PROCESSES": 0,
        "LAUNCH_CAPTURE_CONTENT_ACTIVITY_FOR_NOTE": 0,
        "LAUNCH_MULTI_PANE_SETTINGS_DEEP_LINK": 0,
        "LOADER_USAGE_STATS": 0,
        "LOCATION_HARDWARE": 0,
        "MANAGE_DEVICE_LOCK_STATE": 0,
        "MANAGE_DEVICE_POLICY_ACCESSIBILITY": 0,
        "MANAGE_DEVICE_POLICY_ACCOUNT_MANAGEMENT": 0,
        "MANAGE_DEVICE_POLICY_ACROSS_USERS": 0,
        "MANAGE_DEVICE_POLICY_ACROSS_USERS_FULL": 0,
        "MANAGE_DEVICE_POLICY_ACROSS_USERS_SECURITY_CRITICAL": 0,
        "MANAGE_DEVICE_POLICY_AIRPLANE_MODE": 0,
        "MANAGE_DEVICE_POLICY_APPS_CONTROL": 0,
        "MANAGE_DEVICE_POLICY_APP_FUNCTIONS": 0,
        "MANAGE_DEVICE_POLICY_APP_RESTRICTIONS": 0,
        "MANAGE_DEVICE_POLICY_APP_USER_DATA": 0,
        "MANAGE_DEVICE_POLICY_ASSIST_CONTENT": 0,
        "MANAGE_DEVICE_POLICY_AUDIO_OUTPUT": 0,
        "MANAGE_DEVICE_POLICY_AUTOFILL": 0,
        "MANAGE_DEVICE_POLICY_BACKUP_SERVICE": 0,
        "MANAGE_DEVICE_POLICY_BLOCK_UNINSTALL": 0,
        "MANAGE_DEVICE_POLICY_BLUETOOTH": 0,
        "MANAGE_DEVICE_POLICY_BUGREPORT": 0,
        "MANAGE_DEVICE_POLICY_CALLS": 0,
        "MANAGE_DEVICE_POLICY_CAMERA": 0,
        "MANAGE_DEVICE_POLICY_CAMERA_TOGGLE": 0,
        "MANAGE_DEVICE_POLICY_CERTIFICATES": 0,
        "MANAGE_DEVICE_POLICY_COMMON_CRITERIA_MODE": 0,
        "MANAGE_DEVICE_POLICY_CONTENT_PROTECTION": 0,
        "MANAGE_DEVICE_POLICY_DEBUGGING_FEATURES": 0,
        "MANAGE_DEVICE_POLICY_DEFAULT_SMS": 0,
        "MANAGE_DEVICE_POLICY_DEVICE_IDENTIFIERS": 0,
        "MANAGE_DEVICE_POLICY_DISPLAY": 0,
        "MANAGE_DEVICE_POLICY_FACTORY_RESET": 0,
        "MANAGE_DEVICE_POLICY_FUN": 0,
        "MANAGE_DEVICE_POLICY_INPUT_METHODS": 0,
        "MANAGE_DEVICE_POLICY_INSTALL_UNKNOWN_SOURCES": 0,
        "MANAGE_DEVICE_POLICY_KEEP_UNINSTALLED_PACKAGES": 0,
        "MANAGE_DEVICE_POLICY_KEYGUARD": 0,
        "MANAGE_DEVICE_POLICY_LOCALE": 0,
        "MANAGE_DEVICE_POLICY_LOCATION": 0,
        "MANAGE_DEVICE_POLICY_LOCK": 0,
        "MANAGE_DEVICE_POLICY_LOCK_CREDENTIALS": 0,
        "MANAGE_DEVICE_POLICY_LOCK_TASK": 0,
        "MANAGE_DEVICE_POLICY_MANAGED_SUBSCRIPTIONS": 0,
        "MANAGE_DEVICE_POLICY_METERED_DATA": 0,
        "MANAGE_DEVICE_POLICY_MICROPHONE": 0,
        "MANAGE_DEVICE_POLICY_MICROPHONE_TOGGLE": 0,
        "MANAGE_DEVICE_POLICY_MOBILE_NETWORK": 0,
        "MANAGE_DEVICE_POLICY_MODIFY_USERS": 0,
        "MANAGE_DEVICE_POLICY_MTE": 0,
        "MANAGE_DEVICE_POLICY_NEARBY_COMMUNICATION": 0,
        "MANAGE_DEVICE_POLICY_NETWORK_LOGGING": 0,
        "MANAGE_DEVICE_POLICY_ORGANIZATION_IDENTITY": 0,
        "MANAGE_DEVICE_POLICY_OVERRIDE_APN": 0,
        "MANAGE_DEVICE_POLICY_PACKAGE_STATE": 0,
        "MANAGE_DEVICE_POLICY_PHYSICAL_MEDIA": 0,
        "MANAGE_DEVICE_POLICY_PRINTING": 0,
        "MANAGE_DEVICE_POLICY_PRIVATE_DNS": 0,
        "MANAGE_DEVICE_POLICY_PROFILES": 0,
        "MANAGE_DEVICE_POLICY_PROFILE_INTERACTION": 0,
        "MANAGE_DEVICE_POLICY_PROXY": 0,
        "MANAGE_DEVICE_POLICY_QUERY_SYSTEM_UPDATES": 0,
        "MANAGE_DEVICE_POLICY_RESET_PASSWORD": 0,
        "MANAGE_DEVICE_POLICY_RESTRICT_PRIVATE_DNS": 0,
        "MANAGE_DEVICE_POLICY_RUNTIME_PERMISSIONS": 0,
        "MANAGE_DEVICE_POLICY_RUN_IN_BACKGROUND": 0,
        "MANAGE_DEVICE_POLICY_SAFE_BOOT": 0,
        "MANAGE_DEVICE_POLICY_SCREEN_CAPTURE": 0,
        "MANAGE_DEVICE_POLICY_SCREEN_CONTENT": 0,
        "MANAGE_DEVICE_POLICY_SECURITY_LOGGING": 0,
        "MANAGE_DEVICE_POLICY_SETTINGS": 0,
        "MANAGE_DEVICE_POLICY_SMS": 0,
        "MANAGE_DEVICE_POLICY_STATUS_BAR": 0,
        "MANAGE_DEVICE_POLICY_SUPPORT_MESSAGE": 0,
        "MANAGE_DEVICE_POLICY_SUSPEND_PERSONAL_APPS": 0,
        "MANAGE_DEVICE_POLICY_SYSTEM_APPS": 0,
        "MANAGE_DEVICE_POLICY_SYSTEM_DIALOGS": 0,
        "MANAGE_DEVICE_POLICY_SYSTEM_UPDATES": 0,
        "MANAGE_DEVICE_POLICY_THREAD_NETWORK": 0,
        "MANAGE_DEVICE_POLICY_TIME": 0,
        "MANAGE_DEVICE_POLICY_USB_DATA_SIGNALLING": 0,
        "MANAGE_DEVICE_POLICY_USB_FILE_TRANSFER": 0,
        "MANAGE_DEVICE_POLICY_USERS": 0,
        "MANAGE_DEVICE_POLICY_VPN": 0,
        "MANAGE_DEVICE_POLICY_WALLPAPER": 0,
        "MANAGE_DEVICE_POLICY_WIFI": 0,
        "MANAGE_DEVICE_POLICY_WINDOWS": 0,
        "MANAGE_DEVICE_POLICY_WIPE_DATA": 0,
        "MANAGE_DOCUMENTS": 0,
        "MANAGE_EXTERNAL_STORAGE": 0,
        "MANAGE_MEDIA": 0,
        "MANAGE_ONGOING_CALLS": 0,
        "MANAGE_OWN_CALLS": 0,
        "MANAGE_WIFI_INTERFACES": 0,
        "MANAGE_WIFI_NETWORK_SELECTION": 0,
        "MASTER_CLEAR": 0,
        "MEDIA_CONTENT_CONTROL": 0,
        "MEDIA_ROUTING_CONTROL": 0,
        "MODIFY_AUDIO_SETTINGS": 0,
        "MODIFY_PHONE_STATE": 0,
        "MOUNT_FORMAT_FILESYSTEMS": 0,
        "MOUNT_UNMOUNT_FILESYSTEMS": 0,
        "NEARBY_WIFI_DEVICES": 0,
        "NFC": 0,
        "NFC_PREFERRED_PAYMENT_INFO": 0,
        "NFC_TRANSACTION_EVENT": 0,
        "OVERRIDE_WIFI_CONFIG": 0,
        "PACKAGE_USAGE_STATS": 0,
        "PERSISTENT_ACTIVITY": 0,
        "POST_NOTIFICATIONS": 0,
        "PROCESS_OUTGOING_CALLS": 0,
        "PROVIDE_OWN_AUTOFILL_SUGGESTIONS": 0,
        "PROVIDE_REMOTE_CREDENTIALS": 0,
        "QUERY_ADVANCED_PROTECTION_MODE": 0,
        "QUERY_ALL_PACKAGES": 0,
        "RANGING": 0,
        "READ_ASSISTANT_APP_SEARCH_DATA": 0,
        "READ_BASIC_PHONE_STATE": 0,
        "READ_CALENDAR": 0,
        "READ_CALL_LOG": 0,
        "READ_COLOR_ZONES": 0,
        "READ_CONTACTS": 0,
        "READ_DROPBOX_DATA": 0,
        "READ_EXTERNAL_STORAGE": 0,
        "READ_HOME_APP_SEARCH_DATA": 0,
        "READ_INPUT_STATE": 0,
        "READ_LOGS": 0,
        "READ_MEDIA_AUDIO": 0,
        "READ_MEDIA_IMAGES": 0,
        "READ_MEDIA_VIDEO": 0,
        "READ_MEDIA_VISUAL_USER_SELECTED": 0,
        "READ_NEARBY_STREAMING_POLICY": 0,
        "READ_PHONE_NUMBERS": 0,
        "READ_PHONE_STATE": 0,
        "READ_PRECISE_PHONE_STATE": 0,
        "READ_SMS": 0,
        "READ_SYNC_SETTINGS": 0,
        "READ_SYNC_STATS": 0,
        "READ_SYSTEM_PREFERENCES": 0,
        "READ_VOICEMAIL": 0,
        "REBOOT": 0,
        "RECEIVE_BOOT_COMPLETED": 0,
        "RECEIVE_MMS": 0,
        "RECEIVE_SMS": 0,
        "RECEIVE_WAP_PUSH": 0,
        "RECORD_AUDIO": 0,
        "REORDER_TASKS": 0,
        "REQUEST_COMPANION_PROFILE_APP_STREAMING": 0,
        "REQUEST_COMPANION_PROFILE_AUTOMOTIVE_PROJECTION": 0,
        "REQUEST_COMPANION_PROFILE_COMPUTER": 0,
        "REQUEST_COMPANION_PROFILE_GLASSES": 0,
        "REQUEST_COMPANION_PROFILE_NEARBY_DEVICE_STREAMING": 0,
        "REQUEST_COMPANION_PROFILE_WATCH": 0,
        "REQUEST_COMPANION_RUN_IN_BACKGROUND": 0,
        "REQUEST_COMPANION_SELF_MANAGED": 0,
        "REQUEST_COMPANION_START_FOREGROUND_SERVICES_FROM_BACKGROUND": 0,
        "REQUEST_COMPANION_USE_DATA_IN_BACKGROUND": 0,
        "REQUEST_DELETE_PACKAGES": 0,
        "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": 0,
        "REQUEST_INSTALL_PACKAGES": 0,
        "REQUEST_OBSERVE_COMPANION_DEVICE_PRESENCE": 0,
        "REQUEST_OBSERVE_DEVICE_UUID_PRESENCE": 0,
        "REQUEST_PASSWORD_COMPLEXITY": 0,
        "RESTART_PACKAGES": 0,
        "RUN_USER_INITIATED_JOBS": 0,
        "SCHEDULE_EXACT_ALARM": 0,
        "SEND_RESPOND_VIA_MESSAGE": 0,
        "SEND_SMS": 0,
        "SET_ALARM": 0,
        "SET_ALWAYS_FINISH": 0,
        "SET_ANIMATION_SCALE": 0,
        "SET_BIOMETRIC_DIALOG_ADVANCED": 0,
        "SET_DEBUG_APP": 0,
        "SET_PREFERRED_APPLICATIONS": 0,
        "SET_PROCESS_LIMIT": 0,
        "SET_TIME": 0,
        "SET_TIME_ZONE": 0,
        "SET_WALLPAPER": 0,
        "SET_WALLPAPER_HINTS": 0,
        "SIGNAL_PERSISTENT_PROCESSES": 0,
        "SMS_FINANCIAL_TRANSACTIONS": 0,
        "START_FOREGROUND_SERVICES_FROM_BACKGROUND": 0,
        "START_VIEW_APP_FEATURES": 0,
        "START_VIEW_PERMISSION_USAGE": 0,
        "STATUS_BAR": 0,
        "SUBSCRIBE_TO_KEYGUARD_LOCKED_STATE": 0,
        "SYSTEM_ALERT_WINDOW": 0,
        "TRANSMIT_IR": 0,
        "TURN_SCREEN_ON": 0,
        "TV_IMPLICIT_ENTER_PIP": 0,
        "UNINSTALL_SHORTCUT": 0,
        "UPDATE_DEVICE_STATS": 0,
        "UPDATE_PACKAGES_WITHOUT_USER_ACTION": 0,
        "USE_BIOMETRIC": 0,
        "USE_EXACT_ALARM": 0,
        "USE_FINGERPRINT": 0,
        "WRITE_VOICEMAIL": 0,
        "USE_FULL_SCREEN_INTENT": 0,
        "USE_ICC_AUTH_WITH_DEVICE_IDENTIFIER": 0,
        "USE_SIP": 0,
        "UWB_RANGING": 0,
        "VIBRATE": 0,
        "WAKE_LOCK": 0,
        "WRITE_APN_SETTINGS": 0,
        "WRITE_CALENDAR": 0,
        "WRITE_CALL_LOG": 0,
        "WRITE_CONTACTS": 0,
        "WRITE_EXTERNAL_STORAGE": 0,
        "WRITE_GSERVICES": 0,
        "WRITE_SECURE_SETTINGS": 0,
        "WRITE_SETTINGS": 0,
        "WRITE_SYNC_SETTINGS": 0,
        "WRITE_SYSTEM_PREFERENCES": 0
    }
    os.makedirs("./permissions_data/", exist_ok=True)
    for filename in os.listdir(directory):
        # Get the full filepath for running the command
        analyze = os.path.join(directory, filename)
        apkname = filename.replace('_AndroidManifest.xml', '')
        # Check if it is a file (not a directory)
        if os.path.isfile(analyze):
            output_file_path = os.path.join("./permissions_data/", apkname)
            with open(f"{output_file_path}.csv", "w", encoding="utf-8") as output_file:
                # Write CSV headers
                output_file.write("name,")  # First column is "name"
                output_file.write(",".join(permissions.keys()))  # Permission keys as columns
                output_file.write("\n")  # End of header line
                # Reset permissions for the current file
                current_permissions = permissions.copy()

                # Open and read the manifest file
                try:
                    with open(analyze, "r", encoding="utf-8") as input_file:
                        for line in input_file:
                            for key in current_permissions:
                                if "android.permission." + key in line:
                                    current_permissions[key] = 1
                                    print(f"Found {key} in {filename}")

                    # Write the results to the CSV file
                    output_file.write(
                        ",".join(map(str, current_permissions.values())))  # Write permission values

                    print(f"Processed: {analyze}")

                except Exception as e:
                    print(f"Error processing {analyze}: {e}")


def extract_intent_actions():
    """
    Parses an AndroidManifest.xml file and returns a dictionary
    indicating the presence of common intent actions.

    Returns:
        dict: A dictionary where keys are common intent action strings
              and values are 1 if the action is found in the manifest
              within an <intent-filter>, and 0 otherwise.
    """
    directory = "./manifests/"
    all_intent_actions = {
        "android.intent.action.MAIN": 0,
        "android.intent.action.VIEW": 0,
        "android.intent.action.DIAL": 0,
        "android.intent.action.CALL": 0,
        "android.intent.action.SENDTO": 0,
        "android.intent.action.SEND": 0,
        "android.intent.action.SEND_MULTIPLE": 0,
        "android.intent.action.INSERT": 0,
        "android.intent.action.DELETE": 0,
        "android.intent.action.EDIT": 0,
        "android.intent.action.PICK": 0,
        "android.intent.action.GET_CONTENT": 0,
        "android.intent.action.OPEN_DOCUMENT": 0,
        "android.intent.action.CREATE_DOCUMENT": 0,
        "android.intent.action.CHOOSER": 0,
        "android.intent.action.SEARCH": 0,
        "android.intent.action.WEB_SEARCH": 0,
        "android.intent.action.SYNC": 0,
        "android.intent.action.SET_WALLPAPER": 0,
        "android.intent.action.INSTALL_PACKAGE": 0,
        "android.intent.action.UNINSTALL_PACKAGE": 0,
        "android.intent.action.BOOT_COMPLETED": 0,
        "android.intent.action.MEDIA_MOUNTED": 0,
        "android.intent.action.MEDIA_UNMOUNTED": 0,
        "android.intent.action.ACTION_POWER_CONNECTED": 0,
        "android.intent.action.ACTION_POWER_DISCONNECTED": 0,
        "android.intent.action.BATTERY_LOW": 0,
        "android.intent.action.BATTERY_OKAY": 0,
        "android.intent.action.DEVICE_STORAGE_LOW": 0,
        "android.intent.action.DEVICE_STORAGE_OK": 0,
        "android.intent.action.MANAGE_NETWORK_STORAGE": 0,
        "android.intent.action.LOCALE_CHANGED": 0,
        "android.intent.action.TIME_SET": 0,
        "android.intent.action.TIMEZONE_CHANGED": 0,
        "android.intent.action.REBOOT": 0,
        "android.intent.action.SHUTDOWN": 0,
        "android.intent.action.CONFIGURATION_CHANGED": 0,
        "android.intent.action.CONTENT_CHANGED": 0,
        "android.intent.action.EXTERNAL_APPLICATIONS_AVAILABLE": 0,
        "android.intent.action.EXTERNAL_APPLICATIONS_UNAVAILABLE": 0,
        "android.intent.action.PACKAGE_ADDED": 0,
        "android.intent.action.PACKAGE_CHANGED": 0,
        "android.intent.action.PACKAGE_REMOVED": 0,
        "android.intent.action.PACKAGE_REPLACED": 0,
        "android.intent.action.PACKAGE_RESTARTED": 0,
        "android.intent.action.MY_PACKAGE_REPLACED": 0,
        "android.intent.action.UID_REMOVED": 0,
        "android.intent.action.USER_PRESENT": 0,
        "android.intent.action.QUICK_VIEW": 0,
        "android.intent.action.ASSIST": 0,
        "android.intent.action.BUG_REPORT": 0,
        "android.intent.action.PROCESS_TEXT": 0,
        "android.intent.action.SHOW_APP_INFO": 0,
        "android.intent.action.VOICE_COMMAND": 0,
        "android.intent.action.CREATE_SHORTCUT": 0,
        "android.intent.action.OPEN_DOCUMENT_TREE": 0,
        "android.intent.action.OPEN_EXTERNAL_DIRECTORY": 0,
        "android.intent.action.ADVANCED_SETTINGS": 0,
        "android.intent.action.APPLICATION_DETAILS_SETTINGS": 0,
        "android.intent.action.MANAGE_APPLICATIONS_SETTINGS": 0,
        "android.intent.action.MANAGE_ALL_APPLICATIONS_ACCESS_PERMISSION": 0,
        "android.intent.action.NOTIFICATION_POLICY_ACCESS_SETTINGS": 0,
        "android.intent.action.ACTION_SEARCH_SETTINGS": 0,
        "android.intent.action.SHOW_INPUT_METHOD_PICKER": 0,
        "android.intent.action.SHOW_KEYBOARD_SHORTCUTS": 0,
        "android.intent.action.ACTION_SHOW_WORK_POLICY": 0,
        "android.intent.action.ACTION_SYSTEM_LOCALE_CHANGED": 0,
        "android.intent.action.UPGRADE_ASSISTANT": 0,
        "android.intent.action.AUTO_FILL_SET_SERVICE": 0,
        "android.intent.action.RESOLVE_ACTIVITY": 0,
        "android.intent.action.NEXT": 0,
        "android.intent.action.PREVIOUS": 0,
        "android.intent.action.CLOSE_SYSTEM_DIALOGS": 0,
        "android.intent.action.ALL_APPS": 0,
        "android.intent.action.STK_INVOKE": 0,
        "android.intent.action.STK_CC_OPEN": 0,
        "android.intent.action.STK_CMD": 0,
        "android.intent.action.STK_EVENT": 0,
        "android.intent.action.DEVICE_LOCKED_CHANGED": 0,
        "android.intent.action.PROFILE_PROVISIONING_COMPLETE": 0,
        "android.intent.action.PROFILE_PROVISIONING_ERROR": 0,
        "android.intent.action.PROVISIONING_REQUIRED": 0,
        "android.intent.action.ACTION_SESSION_DETAILS": 0,
        "android.intent.action.VIEW_INSTANT_APP": 0,
        "android.intent.action.START_ACTIVITY_FROM_RECENTS": 0,
        "android.intent.action.SHOW_RECENT_APPS": 0,
        "android.intent.action.GLOBAL_BUTTON": 0,
        "android.intent.action.KEYBOARD_RESOURCE_MAPPING": 0,
        "android.intent.action.MEDIA_BUTTON": 0,
        "android.intent.action.PRE_BOOT_COMPLETED": 0,
        "android.intent.action.UMS_CONNECTED": 0,
        "android.intent.action.UMS_DISCONNECTED": 0,
        "android.intent.action.USER_INITIALIZE": 0,
        "android.intent.action.USER_ADDED": 0,
        "android.intent.action.USER_REMOVED": 0,
        "android.intent.action.USER_STARTED": 0,
        "android.intent.action.USER_STOPPED": 0,
        "android.intent.action.USER_UNLOCKED": 0,
        "android.intent.action.USER_BACKGROUND": 0,
        "android.intent.action.USER_FOREGROUND": 0,
        "android.intent.action.LOCKED_BOOT_COMPLETED": 0,
        "android.intent.action.ACTION_PREFERRED_ACTIVITY_CHANGED": 0,
        "android.intent.action.PACKAGE_DATA_CLEARED": 0,
        "android.intent.action.PACKAGE_FULLY_SUSPENDED": 0,
        "android.intent.action.PACKAGE_UNSUSPENDED": 0,
        "android.intent.action.START_INSTRUMENTATION": 0,
        "android.intent.action.FINISH_INSTRUMENTATION": 0,
        "android.intent.action.GET_PREFERRED_APPLICATIONS": 0,
        "android.intent.action.CLEAR_PREFERRED_APPLICATIONS": 0,
        "android.intent.action.CHANGE_COMPONENT_ENABLED_STATE": 0,
        "android.intent.action.SHOW_SUSPENDED_APP_DETAILS": 0,
        "android.intent.action.REQUEST_OMNIFOCUS": 0,
        "android.intent.action.DISMISS_KEYBOARD": 0,
        "android.intent.action.SHOW_VOICE_INPUT_PICKER": 0,
        "android.intent.action.PROCESS_WIDGETS": 0,
        "android.intent.action.GET_CONTENT_WITH_PERMISSION": 0,
        "android.intent.action.REVIEW_VOICE_INTERACTIONS": 0,
        "android.intent.action.GET_RESTRICTION_ENTRIES": 0,
        "android.intent.action.START_CAPTURE": 0,
        "android.intent.action.STOP_CAPTURE": 0,
        "android.intent.action.SHOW_APP_PREFERENCES": 0,
        "android.intent.action.ENTER_CAR_MODE": 0,
        "android.intent.action.EXIT_CAR_MODE": 0,
        "android.intent.action.SET_MEDIA_PLAYBACK": 0,
        "android.intent.action.PLAY_FROM_SEARCH": 0,
        "android.intent.action.MEDIA_PLAY_FROM_SEARCH": 0,
        "android.intent.action.MEDIA_PAUSE": 0,
        "android.intent.action.MEDIA_PLAY": 0,
        "android.intent.action.MEDIA_PLAY_FROM_URI": 0,
        "android.intent.action.MEDIA_PREPARE": 0,
        "android.intent.action.MEDIA_RECORD": 0,
        "android.intent.action.MEDIA_STOP": 0,
        "android.intent.action.MEDIA_STEP_BACKWARD": 0,
        "android.intent.action.MEDIA_STEP_FORWARD": 0,
        "android.intent.action.MEDIA_STEP_INTO": 0,
        "android.intent.action.MEDIA_STEP_OUT": 0,
        "android.intent.action.ACTION_PLAY_FROM_ID": 0,
        "android.intent.action.ACTION_PLAY_FROM_INDEX": 0,
        "android.intent.action.ACTION_CHANGE_VOLUME": 0,
        "android.intent.action.ACTION_SET_PLAYBACK_SPEED": 0,
        "android.intent.action.ACTION_SET_REPEAT_MODE": 0,
        "android.intent.action.ACTION_HANDLE_MEDIA_KEY": 0,
        "android.intent.action.ACTION_NOTIFY_SESSION_STATE_CHANGED": 0,
        "android.intent.action.ACTION_SET_RINGTONE": 0,
        "android.intent.action.RINGTONE_PICKER": 0,
        "android.intent.action.ACTION_GET_SAMPLE_DATA": 0,
        "android.intent.action.OPEN_DOCUMENT_SETTINGS": 0,
        "android.intent.action.PRINT": 0,
        "android.intent.action.PRINT_DOCUMENT": 0,
        "android.intent.action.PRINT_WRITE": 0,
        "android.intent.action.PRINT_JOB_QUEUED": 0,
        "android.intent.action.PRINT_JOB_STATE_CHANGED": 0,
        "android.intent.action.PRINT_SPOOLER_STARTED": 0,
        "android.intent.action.PRINT_SPOOLER_STOPPED": 0,
        "android.intent.action.VIEW_DOWNLOADS": 0,
        "android.intent.action.DOWNLOAD_COMPLETE": 0,
        "android.intent.action.DOWNLOAD_NOTIFICATION_CLICKED": 0,
        "android.intent.action.RESTART_DOWNLOAD": 0,
        "android.intent.action.ENQUEUE": 0,
        "android.intent.action.PAUSE": 0,
        "android.intent.action.PAUSE_ALL": 0,
        "android.intent.action.RESUME": 0,
        "android.intent.action.RESUME_ALL": 0,
        "android.intent.action.CANCEL": 0,
        "android.intent.action.HIDE": 0,
        "android.intent.action.SHOW": 0,
        "android.intent.action.MIME_TYPE_CHANGED": 0,
        "android.intent.action.SYNC_STATUS_CHANGED": 0,
        "android.intent.action.AUTHENTICATE": 0,
        "android.intent.action.ACCOUNT_REMOVED": 0,
        "android.intent.action.ADD_ACCOUNT": 0,
        "android.intent.action.REQUEST_SYNC": 0,
        "android.intent.action.SEND_MULTIPLE_SYNC": 0,
        "android.intent.action.SEND_SYNC": 0,
        "android.intent.action.SYNC_ERROR": 0,
        "android.intent.action.DISCOVER": 0,
        "android.intent.action.CREATE_ACTION": 0,
        "android.intent.action.RECOGNIZE_SPEECH": 0,
        "android.intent.action.GET_LANGUAGE_DETAILS": 0,
        "android.intent.action.TRANSLATE": 0,
        "android.intent.action.TRANSLATION_SERVICE": 0,
        "android.intent.action.PROVIDE_DEFAULT_VOICE_INTERACTION_SERVICE": 0,
        "android.intent.action.VOICE_ASSIST": 0,
        "android.intent.action.LAUNCH_VOICE_SEARCH": 0,
        "android.intent.action.REPORT_TEXT": 0,
        "android.intent.action.SELECT_TEXT": 0,
        "android.intent.action.SHOW_OR_HIDE_INPUT_METHOD": 0,
        "android.intent.action.TOGGLE_INPUT_METHOD": 0,
        "android.intent.action.PICK_KEYBOARD_LAYOUT": 0,
        "android.intent.action.TOGGLE_INPUT": 0,
        "android.intent.action.CLEAR_APP_CACHE": 0,
        "android.intent.action.CLEAR_APP_DATA": 0,
        "android.intent.action.CLEAR_APP_PREFERRED_SETTINGS": 0,
        "android.intent.action.MANAGE_SPACE": 0,
        "android.intent.action.MANAGE_SPACE_INTERNAL": 0,
        "android.intent.action.MANAGE_APP_PERMISSIONS": 0,
        "android.intent.action.MANAGE_DEFAULT_APPS_SETTINGS": 0,
        "android.intent.action.MANAGE_ROLE_ACCESS": 0,
        "android.intent.action.REQUEST_INSTALL_PACKAGES": 0,
        "android.intent.action.VIEW_APP_DETAILS": 0,
        "android.intent.action.REQUEST_DELETE_PACKAGES": 0,
        "android.intent.action.REQUEST_SCAN_FILE": 0,
        "android.intent.action.RESPOND_VIA_MESSAGE": 0,
        "android.intent.action.SEND_MESSAGE": 0,
        "android.intent.action.AUTO_SEND": 0,
        "android.intent.action.ECM_CHANGED": 0,
        "android.intent.action.ACTION_SHOW_CURRENT_PERMISSION_GRANTS": 0,
        "android.intent.action.ACTION_VOICE_SESSION": 0,
        "android.intent.action.DIAL_EMERGENCY": 0,
        "android.intent.action.CALL_EMERGENCY": 0,
        "android.intent.action.CONFIGURE_VOICEMAIL": 0,
        "android.intent.action.CHECK_VOICEMAIL": 0,
        "android.intent.action.ADD_VOICEMAIL": 0,
        "android.intent.action.ACTION_ ক্যারি_ON_SUBSCRIPTION": 0,
        "android.intent.action.ACTION_CONFIGURE_PHONE_ACCOUNT": 0,
        "android.intent.action.ACTION_CHANGE_PHONE_ACCOUNT": 0,
        "android.intent.action.ACTION_DISABLE_SELF_CALL": 0,
        "android.intent.action.ACTION_SHOW_SUBSCRIPTION_SETTING": 0,
        "android.intent.action.ACTION_MANAGE_SUBSCRIPTION_PLANS": 0,
        "android.intent.action.ACTION_PERFORM_VOICE_CALL": 0,
        "android.intent.action.ACTION_PERFORM_VIDEO_CALL": 0,
        "android.intent.action.ACTION_PERFORM_IMS_CALL": 0,
        "android.intent.action.ACTION_PERFORM_RTT_CALL": 0,
        "android.intent.action.ACTION_SHOW_CALL_SCREEN": 0,
        "android.intent.action.ACTION_SHOW_CALL_HISTORY": 0,
        "android.intent.action.ACTION_ADD_CALL": 0,
        "android.intent.action.ACTION_ANSWER": 0,
        "android.intent.action.ACTION_ANSWER_VIDEO": 0,
        "android.intent.action.ACTION_DECLINE": 0,
        "android.intent.action.ACTION_HANG_UP": 0,
        "android.intent.action.ACTION_CHANGE_DEFAULT": 0,
        "android.intent.action.ACTION_CHANGE_DEFAULT_DIALER": 0,
        "android.intent.action.ACTION_GET_DEFAULT_SUBSCRIPTION_ID": 0,
        "android.intent.action.ACTION_SHOW_MISSED_CALLS": 0,
        "android.intent.action.ACTION_PLUG_IN_MANAGED_PROFILE": 0,
        "android.intent.action.ACTION_PROVISION_MANAGED_PROFILE": 0,
        "android.intent.action.ACTION_INSTALL_PACKAGE_SESSION": 0,
        "android.intent.action.ACTION_COMMIT_SESSION": 0,
        "android.intent.action.ACTION_ABANDON_SESSION": 0,
        "android.intent.action.ACTION_OPEN_APP_PERMISSION_SETTINGS": 0,
        "android.intent.action.ACTION_REVIEW_PERMISSIONS": 0,
        "android.intent.action.ACTION_APPLICATION_PREFERENCES": 0,
        "android.intent.action.VIEW_CONTENT": 0,
        "android.intent.action.EDIT_CONTENT": 0,
        "android.intent.action.PICK_ACTIVITY": 0,
        "android.intent.action.BROWSE": 0,
        "android.intent.action.INSERT_CALENDAR_EVENT": 0,
        "android.intent.action.INSERT_CONTACT": 0,
        "android.intent.action.ADD_TO_HOME_SCREEN": 0,
        "android.intent.action.INSTALL_SHORTCUT": 0,
        "android.intent.action.UNINSTALL_SHORTCUT": 0,
        "android.intent.action.DREAMING_STARTED": 0,
        "android.intent.action.DREAMING_STOPPED": 0,
        "android.intent.action.SCREEN_OFF": 0,
        "android.intent.action.SCREEN_ON": 0,
        "android.intent.action.ACTION_DOCK_EVENT": 0,
        "android.intent.action.ACTION_HEADSET_PLUG": 0,
        "android.intent.action.ACTION_NEW_OUTGOING_CALL": 0,
        "android.intent.action.PHONE_STATE": 0,
        "android.intent.action.ACTION_EXTERNAL_STORAGE_MOUNTED": 0,
        "android.intent.action.ACTION_EXTERNAL_STORAGE_UNMOUNTED": 0,
        "android.intent.action.ACTION_GTALK_SERVICE_CONNECTED": 0,
        "android.intent.action.ACTION_GTALK_SERVICE_DISCONNECTED": 0,
        "android.intent.action.INPUT_METHOD_CHANGED": 0,
        "android.intent.action.NEW_PICTURE": 0,
        "android.intent.action.NEW_VIDEO": 0,
        "android.intent.action.PROVIDER_CHANGED": 0,
        "android.intent.action.PROXY_CHANGE": 0,
        "android.intent.action.REBOOT_REQUIRED": 0,
        "android.intent.action.SEARCH_LONG_PRESS": 0
    }
    os.makedirs("./intents_data/", exist_ok=True)
    for filename in os.listdir(directory):
        all_current_intents = all_intent_actions.copy()
        apkname = filename.replace('_AndroidManifest.xml', '')
        output_file_path = os.path.join("./intents_data/", apkname)
        with open(f"{output_file_path}.csv", "w", encoding="utf-8") as output_file:
            # Write CSV headers
            output_file.write("name,")  # First column is "name"
            output_file.write(",".join(all_intent_actions.keys()))  # Permission keys as columns
            output_file.write("\n")  # End of header line
            try:
                analyze = os.path.join(directory, filename)
                tree = ET.parse(analyze)
                root = tree.getroot()

                for activity in root.findall('.//activity'):
                    for intent_filter in activity.findall('./intent-filter'):
                        for action_element in intent_filter.findall('./action'):
                            action = action_element.get('{http://schemas.android.com/apk/res/android}name')
                            if action in all_intent_actions:
                                all_current_intents[action] = 10

                for receiver in root.findall('.//receiver'):
                    for intent_filter in receiver.findall('./intent-filter'):
                        for action_element in intent_filter.findall('./action'):
                            action = action_element.get('{http://schemas.android.com/apk/res/android}name')
                            if action in all_intent_actions:
                                all_current_intents[action] = 11

                for service in root.findall('.//service'):
                    for intent_filter in service.findall('./intent-filter'):
                        for action_element in intent_filter.findall('./action'):
                            action = action_element.get('{http://schemas.android.com/apk/res/android}name')
                            if action in all_intent_actions:
                                all_current_intents[action] = 12
                output_file.write(",".join(map(str, all_current_intents.values())))  # Write permission values
            except ET.ParseError:
                print(f"Error: Could not parse the XML file {filename}")


def extract_sensitive_apis():
    directory = './callgraphs/'
    os.makedirs("./sensitive_apis_data/", exist_ok=True)
    for filename in os.listdir(directory):
        apkname = filename.replace('_callgraph.xml', '')
        analyze = os.path.join(directory, filename)
        output_file_path = os.path.join("./sensitive_apis_data/", apkname)
        with open(f"{output_file_path}.txt", "w", encoding="utf-8") as output_file:
            #Reading the Callgraphs created using androguard tool
            G2 = nx.read_gml(analyze, label='label')

            # List containing the names of all the sensitive API classes.
            sensitive_api = ['TelephonyManager', 'SmsManager', 'LocationManager', 'AudioManager', 'HttpURLConnection',
                             'ConnectivityManager', 'BroadcastReceiver', 'Cipher', 'AccessibleObject', 'PackageManager']

            sensitive_api_malware = []

            count_api_in_malware = 0

            # Using Regex to fetch all the sensitive API calls from the call graphs and counting the TOTAL number of sensitive API in Application
            for j in sensitive_api:
                for i in G2.nodes():
                    data = re.split('[;]', i)
                    data1 = re.split('/', data[0])
                    for k in data1:
                        if k in sensitive_api:
                            if i in sensitive_api_malware:
                                continue
                            else:
                                sensitive_api_malware.append(i)
                                count_api_in_malware = count_api_in_malware + 1

            print('\033[93m' + "Total Sensitive API Calls found in the MALWARE: " + str(count_api_in_malware))

            # Reading the graph of the Application
            G = nx.read_gml('callgraph.gml', label='id')

            data = []

            b = nx.get_node_attributes(G, 'label')

            for keys, values in b.items():
                splitting = re.split('[[]', values)
                if splitting[0] in sensitive_api_malware:
                    data.append(keys)

            # Getting the CALLER and CALLEE relationship between the Sensitive API's fetched above.
            listing = []
            U = nx.DiGraph()
            counter_in_degree = 0
            for i in data:

                a = G.in_edges(i)
                for j in a:
                    b = list(j)
                    for k in b:
                        if k in data:
                            if G.nodes[k]['label'] not in listing:
                                listing.append(G.nodes[k]['label'])
                                counter_in_degree = counter_in_degree + G.in_degree(i)
                            else:
                                continue
                        else:
                            continue

            # Sorting the API names in ascending order to construct a DiGraph showing a relation between caller and callee.
            sensitive_api_in_malware_name = []
            for el in sorted(listing):
                sensitive_api_in_malware_name.append(el)

            for i in range(0, len(sensitive_api_in_malware_name)):
                # print('\033[96m' + sensitive_api_in_malware_name[i])
                output_file.write(sensitive_api_in_malware_name[i])
                output_file.write("\n")


def extract_static_data(directory):
    extract_manifests(directory)
    extract_permissions()
    extract_intent_actions()

def extract_dynamic_data(directory):
    extract_callgraph(directory)
    extract_sensitive_apis()



if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py <filepath>")
        sys.exit(1)

    apkdirectory = sys.argv[1]

    if os.path.isdir(apkdirectory):
        print(f"Apk Directory path provided: {apkdirectory}")
    else:
        print(f"Invalid Apk directory path: {apkdirectory}")

    process1 = multiprocessing.Process(target=extract_static_data(apkdirectory))
    process2 = multiprocessing.Process(target=extract_dynamic_data(apkdirectory))

    process1.start()
    process2.start()

    process1.join()
    process2.join()

    print("Done")
