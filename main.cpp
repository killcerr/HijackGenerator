#include <LIEF/PE.hpp> // IWYU pragma: keep

#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <string>

#define _AMD64_
#include <libloaderapi.h>
#include <winerror.h>
#include <winreg.h>

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383

std::set<std::string> knownDlls;

std::string generate_single_function(std::string_view name,
                                     std::string_view exp) {
  constexpr auto signleFunction = R"(
#pragma comment(linker, "/export:{0}={1}")
extern "C" auto {1} = GetProcAddress(dll, "{0}");
)";
  return std::format(signleFunction, name, exp);
}

std::string generate_dll(std::string_view abs,
                         const std::vector<std::string> &funcs) {
  constexpr auto libBegin = R"_(
#define _AMD64_
#include "libloaderapi.h"
auto dll = LoadLibrary(R"({})");
)_";
  std::string result = std::format(libBegin, abs);
  for (std::size_t i = 0; auto &func : funcs) {
    result += generate_single_function(func, "export" + std::to_string(i++));
  }
  return result;
}

std::string lowerString(std::string_view str) {
  std::string res;
  for (auto c : str) {
    res += tolower(c);
  }
  return res;
}

void initKnownDlls() {
  HKEY hKey;
  LPCSTR subKey =
      R"(SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs)";
  DWORD dwDisposition;
  LSTATUS status = RegCreateKeyExA(HKEY_LOCAL_MACHINE, subKey, 0, NULL,
                                   REG_OPTION_NON_VOLATILE, KEY_READ, NULL,
                                   &hKey, &dwDisposition);
  char achKey[MAX_KEY_LENGTH];
  DWORD cbName = 0;
  char achClass[MAX_PATH]{0};
  DWORD cchClassName = MAX_PATH;
  DWORD cSubKeys = 0;
  DWORD cbMaxSubKey = 0;
  DWORD cchMaxClass = 0;
  DWORD cValues = 0;
  DWORD cchMaxValue = 0;
  DWORD cbMaxValueData = 0;
  DWORD cbSecurityDescriptor = 0;
  FILETIME ftLastWriteTime;
  DWORD i = 0, j = 0, retCode = 0;
  char achValue[MAX_VALUE_NAME]{0};
  DWORD cchValue = MAX_VALUE_NAME;
  retCode = ::RegQueryInfoKeyA(hKey, achClass, &cchClassName, NULL, &cSubKeys,
                               &cbMaxSubKey, &cchMaxClass, &cValues,
                               &cchMaxValue, &cbMaxValueData,
                               &cbSecurityDescriptor, &ftLastWriteTime);
  if (cValues) {
    for (i = 0; i < cValues; i++) {
      cchValue = MAX_VALUE_NAME;
      achValue[0] = '\0';
      retCode =
          ::RegEnumValue(hKey, i, achValue, &cchValue, NULL, NULL, NULL, NULL);
      if (retCode == ERROR_SUCCESS) {
        char data[1024]{0};
        DWORD sz{1024};
        RegGetValueA(hKey, NULL, achValue, RRF_RT_ANY, NULL, data, &sz);
        knownDlls.insert(lowerString(data));
      }
    }
  }
  RegCloseKey(hKey);
  std::cout << "known dlls:" << std::endl;
  for (auto &dll : knownDlls) {
    std::cout << "\t" << dll << std::endl;
  }
}
int main(int argc, char **argv) {
  initKnownDlls();
  if (argc != 2) {
    return 1;
  }
  auto pe = LIEF::PE::Parser::parse(argv[1]);
  std::map<std::string, std::vector<std::string>> dlls;
  for (auto &import : pe->imports()) {
    if (knownDlls.contains(lowerString(import.name())))
      continue;
    if (import.name().starts_with("api-ms-win"))
      continue;
    if (lowerString(import.name()) == "msvcp140.dll")
      continue;
    std::cout << import.name() << std::endl;
    dlls[import.name()] = {};
  }
  auto oldCurrent = std::filesystem::absolute(std::filesystem::current_path());
  std::filesystem::current_path(
      std::filesystem::path{argv[1]}.remove_filename());
  for (auto &[dllname, funcs] : dlls) {
    auto handle =
        LoadLibraryEx(dllname.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!handle)
      continue;
    char filename[1024]{0};
    if (!GetModuleFileName(handle, filename, 1024)) {
      FreeLibrary(handle);
      continue;
    }
    FreeLibrary(handle);
    std::string path = filename;
    auto dll = LIEF::PE::Parser::parse(path);
    std::cout << path << "\n";
    for (auto &exp : dll->exported_functions()) {
      std::cout << "\t" << exp.name() << std::endl;
      funcs.emplace_back(exp.name());
    }
    auto source = generate_dll(path, funcs);
    std::ofstream(oldCurrent / (dllname + ".cpp")) << source;
  }
}