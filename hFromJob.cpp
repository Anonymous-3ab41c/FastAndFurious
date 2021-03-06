#include <Windows.h>
#include <Psapi.h>
#include <iostream>

auto HandleReceiver(HANDLE *ioPort) {
	DWORD nOfBytes;
	ULONG_PTR cKey;
	LPOVERLAPPED pid;
	char processName[MAX_PATH];
	while (GetQueuedCompletionStatus(*ioPort, &nOfBytes, &cKey, &pid, -1))
		if (nOfBytes == 6) {
			auto const hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, reinterpret_cast<DWORD>(pid));
			GetModuleFileNameExA(hProcess, nullptr, processName, MAX_PATH);
			std::cout << "New handle : 0x" << std::hex << std::uppercase << hProcess << " for PID " << pid << " (" << processName << ")" << std::endl;
		}
}

int main() {
	DWORD pid = NULL;
	auto const hwndDesk = GetShellWindow();
	GetWindowThreadProcessId(hwndDesk, &pid);
	auto const hProcess = OpenProcess(PROCESS_ALL_ACCESS, true, pid);
	auto hIoPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 0);
	auto const hJobObject = CreateJobObjectW(nullptr, nullptr);
	auto jobjIoPort = JOBOBJECT_ASSOCIATE_COMPLETION_PORT{ nullptr, hIoPort };
	auto result = SetInformationJobObject(hJobObject, JobObjectAssociateCompletionPortInformation, &jobjIoPort, sizeof(jobjIoPort));
	result = AssignProcessToJobObject(hJobObject, hProcess);
	auto const hThread = CreateThread(nullptr, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(HandleReceiver), &hIoPort, 0, nullptr);
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hProcess);
	return EXIT_SUCCESS;
}