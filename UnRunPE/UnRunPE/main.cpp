#include <iostream>
#include <string>
#include <vector>
#include <ctime>
#include <Windows.h>

#include "static.h"
#include "dynamic.h"
#include "Util.h"

void randomiseColour(char c) {
	// change console colours
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	::GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
	// randomise colour
	std::vector<WORD> allColours({ FOREGROUND_BLUE, FOREGROUND_GREEN, FOREGROUND_RED,
									FOREGROUND_BLUE | FOREGROUND_RED, FOREGROUND_BLUE | FOREGROUND_GREEN, FOREGROUND_BLUE | FOREGROUND_RED | FOREGROUND_INTENSITY, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY,
									FOREGROUND_RED | FOREGROUND_GREEN, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY,
									FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY});

	WORD colour = allColours.at(std::rand() % allColours.size());

	::SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), colour);

	std::cout << c;

	// revert console colours
	::SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), csbi.wAttributes);
}

/*
Syntax: unrunpe.exe [-d] [-f target] [-o output]

*/
int main(int argc, char *argv[]) {
	std::srand((unsigned int)__rdtsc());	// rdtsc because only skrubs use time(0) >:)

	std::string title = "\n" \
		"   _/    _/            _/_/_/                        _/_/_/    _/_/_/_/   \n"\
		"  _/    _/  _/_/_/    _/    _/  _/    _/  _/_/_/    _/    _/  _/          \n"\
		" _/    _/  _/    _/  _/_/_/    _/    _/  _/    _/  _/_/_/    _/_/_/       \n"\
		"_/    _/  _/    _/  _/    _/  _/    _/  _/    _/  _/        _/            \n"\
		" _/_/    _/    _/  _/    _/    _/_/_/  _/    _/  _/        _/_/_/_/       \n\n";

	for (auto c : title) {
		randomiseColour(c);
	}

	if (argc < 3) {
		std::cout << "Syntax: " << argv[0] << " [-s|-d] [-f target] [-o output]\n";
		return 1;
	}

	bool dynamicAnalysis = false;
	std::string target, output;
	for (int i = 0; i < argc; i++) {
		std::string arg = argv[i];
		if (!arg.compare("-d"))	// dynamic analysis
			dynamicAnalysis = true;
		else if (!arg.compare("-f"))	// target file name
			target = argv[i + 1];
		else if (!arg.compare("-o"))	// output file name
			output = argv[i + 1];
	}

	// check number of arguments and proper usage
	// if 2 args, make sure it is [-s|-d] and [-f], i.e., output must not exist
	if (argc == 4 && !output.empty()) {	// check if output is empty
		std::cout << "Syntax: " << argv[0] << " [-s|-d] [-f target] [-o output]\n";
		return 1;
	} else if (argc == 5 && (target.empty() || output.empty())) {
		std::cout << "Syntax: " << argv[0] << " [-s|-d] [-f target] [-o output]\n";
		return 1;
	}

	// always statically analyse
	Util::Debug<Util::DebugType::INFO>("Performing static analysis...\n");
	if (!staticAnalyse(target)) {
		Util::Debug<Util::DebugType::SUB>("Error: " + std::to_string(::GetLastError()) + "\n");
		std::cout << "\n";
	}

	if (!stringAnalyse(target)) {
		Util::Debug<Util::DebugType::SUB>("Error: " + std::to_string(::GetLastError()) + "\n");
		std::cout << "\n";
	}

	if (dynamicAnalysis) {
		Util::Debug<Util::DebugType::INFO>("Performing dynamic analysis...\n");
		dynamicAnalyse(target);
	}

	return 0;
}