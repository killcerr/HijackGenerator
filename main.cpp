#include <LIEF/PE.hpp> // IWYU pragma: keep

#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <string>

#define _AMD64_
#include <libloaderapi.h>

std::set<std::string> protectedDlls = {
    "comctl32.dll",  "comdlg32.dll",
    "crypt32.dll",   "imagehlp.dll",
    "imm32.dll",     "kernelbase.dll",
    "msctf.dll",     "msvcrt.dll",
    "normaliz.dll",  "nsi.dll",
    "oleaut32.dll",  "psapi.dll",
    "shcore.dll",    "shell32.dll",
    "shlwapi.dll",   "setupapi.dll",
    "wintrust.dll",  "wldap32.dll",
    "ws2_32.dll",    "advapi32.dll",
    "bcrypt.dll",    "bcryptprimitives.dll",
    "cfgmgr32.dll",  "clbcatq.dll",
    "combase.dll",   "coml2.dll",
    "difxapi.dll",   "gdi32.dll",
    "gdi32full.dll", "gdiplus.dll",
    "kernel32.dll",  "mscoree.dll",
    "msvcp_win.dll", "ntdll.dll",
    "ole32.dll",     "rpcrt4.dll",
    "sechost.dll",   "ucrtbase.dll",
    "user32.dll",    "win32u.dll",
    "wow64.dll",     "wow64cpu.dll",
    "wow64win.dll",  "msvcp140.dll",
};

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

int main(int argc, char **argv) {
  auto pe = LIEF::PE::Parser::parse(argv[1]);
  std::map<std::string, std::vector<std::string>> dlls;
  for (auto &import : pe->imports()) {
    if (protectedDlls.contains(lowerString(import.name())))
      continue;
    if (import.name().starts_with("api-ms-win"))
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