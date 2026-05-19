#pragma once

// Dialog
#define IDD_SETTINGS                100

// License type group + mode tri-state
#define IDC_GROUP_LICENSE           110
#define IDC_CHK_FULL_INSTALL        113     // tri-state: checked=full, indeterminate=extras-only
#define IDC_RADIO_DONGLE            111
#define IDC_RADIO_BYOD              112

// Credentials group — single visible row; the group title rewrites to
// "Dongle credentials" / "BYOD credentials" as the License radio changes,
// and the field contents swap from the matching saved/in-memory slot.
#define IDC_GROUP_CREDS             120
#define IDC_LABEL_USER              122
#define IDC_EDIT_USER               123
#define IDC_LABEL_PASS              124
#define IDC_EDIT_PASS               125
#define IDC_BTN_TOGGLE_PASS         126
#define IDC_BTN_TEST                127
#define IDC_CHK_REMEMBER_CREDS      135

// Version group
#define IDC_GROUP_VERSION           140
#define IDC_LABEL_DETECTED_PREFIX   146     // "Detected current install:" (regular black)
#define IDC_LABEL_DETECTED          141     // "<host string>" (blue, bold)
#define IDC_LABEL_VERSION           142
#define IDC_COMBO_VERSION           143
#define IDC_BTN_REFRESH_VERSIONS    144
#define IDC_CHK_INCLUDE_BETA        145

// Install location group
#define IDC_GROUP_INSTALL           150
#define IDC_LABEL_INSTALL_BASE      151
#define IDC_EDIT_INSTALL_BASE       152
#define IDC_BTN_BROWSE_INSTALL_BASE 153
#define IDC_LABEL_FOLDER_NAME       154
#define IDC_EDIT_FOLDER_NAME        155
#define IDC_STATIC_FOLDER_HINT      156
#define IDC_LABEL_FOLDER_EXISTS     157     // red-bold "Folder already exists" warning

// Optional downloads group
#define IDC_GROUP_OPTIONAL          160
#define IDC_CHK_DL_VIEWER           161
#define IDC_CHK_DL_TESSERACT        162
#define IDC_CHK_DL_EXCIRE           163
#define IDC_CHK_DL_COND_COLORING    164
#define IDC_CHK_DL_AFF4             165

// Copy from current install group
#define IDC_GROUP_COPY              170
#define IDC_CHK_COPY_CFG            171
#define IDC_CHK_COPY_HASHDB         172
#define IDC_CHK_COPY_XTENSIONS      173

// Shortcut group
#define IDC_GROUP_SHORTCUT          180
#define IDC_CHK_CREATE_SHORTCUT     181
// IDC_CHK_SHORTCUT_ADMIN removed — admin flags are now always-on by default.

// Action buttons
#define IDC_BTN_INSTALL             191
#define IDC_BTN_ABOUT               192
#define IDC_BTN_OPEN_FOLDER         193     // opens the running install in Explorer
#define IDC_PROGRESS_INSTALL        194     // msctls_progress32, range 0..1000, hidden until install starts
#define IDC_LABEL_PROGRESS_STATUS   195     // status text shown above progress bar during install
// IDOK / IDCANCEL come from windows.h

// Custom messages posted from the worker thread to the settings dialog
// during an install run. See WM_APP+N handlers in SettingsDlgProc.
//   WM_APP_PROGRESS:  wParam = permille (0..1000), lParam = unused
//   WM_APP_STATUS:    lParam = heap-allocated wchar_t* (dialog frees)
//   WM_APP_DONE:      wParam = ok flag (1=success), lParam = unused (worker
//                     keeps result struct alive until dialog signals it)
//   WM_APP_MARQUEE:   wParam = 1 to start marquee animation (used during the
//                     post-download tail where bytes-based % stops advancing),
//                     0 to stop and pin the bar back to 100%.
#define WM_APP_PROGRESS             (WM_APP + 1)
#define WM_APP_STATUS               (WM_APP + 2)
#define WM_APP_DONE                 (WM_APP + 3)
#define WM_APP_MARQUEE              (WM_APP + 4)

// About dialog (separate modal)
#define IDD_ABOUT                   200
#define IDC_ABOUT_TITLE             201
#define IDC_ABOUT_DESC              202
#define IDC_ABOUT_DETECTED          203     // rendered in bold blue via WM_CTLCOLORSTATIC (legacy, unused)
#define IDC_ABOUT_AUTHOR            204
#define IDC_ABOUT_LINK_GITHUB       205     // pushbutton — ShellExecute the URL on click
#define IDC_ABOUT_LINK_LINKEDIN     206
#define IDC_ABOUT_LABEL_LIKE        207     // legacy — no longer placed in the dialog
#define IDC_ABOUT_BTN_COFFEE        208     // pushbutton — opens buymeacoffee link
#define IDC_ABOUT_LABEL_AUTHOR_PREFIX 209   // bold "Author:" prefix

// Timer IDs
#define TIMER_REFRESH_FLASH         2001
#define TIMER_FIELD_FLASH           2002
#define TIMER_SHIFT_POLL            2003
