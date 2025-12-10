#pragma once
#include "common.hpp"
#include <map>
#include <functional>
#include <iostream>

#include <string>
#include <sstream>
#include <vector>
#include <cstring>

///str






///////////// ----------------- Custom Commands ----------------- //////////////



BOOL CustomCommand(const char* command, std::string* output);
std::vector<std::string> SplitArgs(const std::string& input);
void Upload(const std::vector<std::string>& args);
void CustomSleepCmd(const std::vector<std::string>& args);

void RegisterCommand(const std::string& name, std::function<void(const std::vector<std::string>&)> func);







