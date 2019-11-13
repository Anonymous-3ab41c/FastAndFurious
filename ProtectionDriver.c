#include <ntddk.h>
#include <ntstrsafe.h>

#define PROTECTED_PROCESS_NAME "Protected.exe"
#define PROCESS_POOL_TAG 'pPR'
#define DEBUG_MSG_LEVEL DPFLTR_INFO_LEVEL
#define NEW_HANDLE_PERMISSION 0x1000 // PROCESS_QUERY_LIMITED_INFORMATION (Too aggressive, will cause suspension of process at launch)
#define PROCESS_TERMINATE 0x0001

NTSYSCALLAPI NTSTATUS NTAPI ZwQueryInformationProcess(
	_In_ HANDLE ProcessHandle,
	_In_ PROCESSINFOCLASS ProcessInformationClass,
	_Out_ PVOID ProcessInformation,
	_In_ ULONG ProcessInformationLength,
	_Out_opt_ PULONG ReturnLength
);

DRIVER_INITIALIZE DriverEntry;

PVOID pCallbackHandle = NULL;
HANDLE hProtectedProcessId = NULL;

HANDLE GetProcessHandle(HANDLE ProcessId, ACCESS_MASK AccessMask) {
	HANDLE hProcess = NULL;
	OBJECT_ATTRIBUTES objAttr;
	CLIENT_ID cid;
	cid.UniqueProcess = ProcessId;
	cid.UniqueThread = NULL;
	InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
	ZwOpenProcess(&hProcess, AccessMask, &objAttr, &cid);
	return hProcess;
}

BOOLEAN IsProtectedProcess(HANDLE ProcessId, PCSZ ProtectedProcessName) {
	NTSTATUS status = STATUS_SUCCESS;

	HANDLE hProcess = GetProcessHandle(ProcessId, PROCESS_ALL_ACCESS);
	if (hProcess == NULL) return FALSE;

	// Getting process image name length
	ULONG ulProcessNameLength = 0;
	status = ZwQueryInformationProcess(hProcess, ProcessImageFileName, NULL, 0, &ulProcessNameLength);

	// Making buffer for process image name
	PVOID pBufferProcessName = ExAllocatePoolWithTag(NonPagedPool, ulProcessNameLength, PROCESS_POOL_TAG);
	if (pBufferProcessName == NULL) {
		status = ObCloseHandle(hProcess, KernelMode);
		return FALSE;
	}

	// Getting process image name into buffer
	status = ZwQueryInformationProcess(hProcess, ProcessImageFileName, pBufferProcessName, ulProcessNameLength, &ulProcessNameLength);

	// Putting into a UNICODE_STRING and converting to an ANSI_STRING
	UNICODE_STRING ustrProcessName;
	if (NT_SUCCESS(status))
		ustrProcessName = *(PUNICODE_STRING)pBufferProcessName;
	ANSI_STRING astrProcessName;
	RtlUnicodeStringToAnsiString(&astrProcessName, &ustrProcessName, TRUE);

	// Getting only the image name, removing the path
	ULONG ulLastBackSlash = 0;
	for (ULONG i = 0; i < ulProcessNameLength; ++i)
		if (astrProcessName.Buffer[i] == '\\')
			ulLastBackSlash = i;
	ULONG ulProcessImageNamePos = 0;
	if (ulLastBackSlash > 0 && ulLastBackSlash < ulProcessNameLength)
		ulProcessImageNamePos = ulLastBackSlash + 1;
	ANSI_STRING astrProcessImageName;
	const uintptr_t uiptrAddrImageName = (uintptr_t)astrProcessName.Buffer + ulProcessImageNamePos;
	RtlInitAnsiString(&astrProcessImageName, (PCSZ)uiptrAddrImageName);

	// Sets protection if this is our protected process
	BOOLEAN isProtectedProcess = FALSE;
	if (strcmp(astrProcessImageName.Buffer, ProtectedProcessName) == 0)
		isProtectedProcess = TRUE;

	// Clean up, frees buffer and close handle
	ExFreePoolWithTag(pBufferProcessName, PROCESS_POOL_TAG);
	status = ObCloseHandle(hProcess, KernelMode);

	return isProtectedProcess;
}

VOID ProtectionDriverPostCalbackOperation(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION OperationInformation) {
	UNREFERENCED_PARAMETER(RegistrationContext);
	UNREFERENCED_PARAMETER(OperationInformation);
}

OB_PREOP_CALLBACK_STATUS ProtectionDriverPreCalbackOperation(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation) {
	UNREFERENCED_PARAMETER(RegistrationContext);

	HANDLE TargetProcessId = PsGetProcessId((PEPROCESS)OperationInformation->Object);

	if (TargetProcessId != hProtectedProcessId)
		return OB_PREOP_SUCCESS;
	
	if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
		//OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = NEW_HANDLE_PERMISSION; // Too agrressive: Will modify handle of critical system processes (e.g. CSRSS, LSASS, etc...) and the program will be suspended at launch.
		if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE)
			OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_MSG_LEVEL, "Handle permission modified! (Target PID %d, requested 0x%x, got 0x%x)\n", TargetProcessId, OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess, OperationInformation->Parameters->CreateHandleInformation.DesiredAccess);
	}

	return OB_PREOP_SUCCESS;
}

NTSTATUS ProtectionDriverSetProtection() {
	OB_OPERATION_REGISTRATION obCallbackOperation;
	OB_CALLBACK_REGISTRATION obCallbackRegistration;
	memset(&obCallbackOperation, 0, sizeof(OB_OPERATION_REGISTRATION));
	memset(&obCallbackRegistration, 0, sizeof(OB_CALLBACK_REGISTRATION));

	obCallbackOperation.ObjectType = PsProcessType;
	obCallbackOperation.Operations |= OB_OPERATION_HANDLE_CREATE;
	obCallbackOperation.Operations |= OB_OPERATION_HANDLE_DUPLICATE;
	obCallbackOperation.PostOperation = ProtectionDriverPostCalbackOperation;
	obCallbackOperation.PreOperation = ProtectionDriverPreCalbackOperation;

	UNICODE_STRING ustrAltitude;
	RtlInitUnicodeString(&ustrAltitude, L"1000");

	obCallbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
	obCallbackRegistration.OperationRegistrationCount = (USHORT)1;
	obCallbackRegistration.RegistrationContext = NULL;
	obCallbackRegistration.Altitude = ustrAltitude;
	obCallbackRegistration.OperationRegistration = &obCallbackOperation;

	return ObRegisterCallbacks(&obCallbackRegistration, &pCallbackHandle);
}

NTSTATUS ProtectionDriverFindProtected(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create) {
	UNREFERENCED_PARAMETER(ParentId);
	if (!Create) return STATUS_SUCCESS;

	if (IsProtectedProcess(ProcessId, PROTECTED_PROCESS_NAME))
		hProtectedProcessId = ProcessId;

	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_MSG_LEVEL, "ProtectionDriver loading ... ");

	PsSetCreateProcessNotifyRoutine(ProtectionDriverFindProtected, FALSE);
	ProtectionDriverSetProtection();
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_MSG_LEVEL, "Ready.\n");
	return STATUS_SUCCESS;
}