// MIT License
//
// Copyright (c) 2023 pTerrance
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <windows.h>
#include <tlhelp32.h>

#include "spdlog/spdlog.h"

#include "memory.h"

namespace comm {

class Toolhelp32Snapshot {
 public:
  Toolhelp32Snapshot(const DWORD flags, const DWORD pid) noexcept :
    snapshot_(CreateToolhelp32Snapshot(flags, pid)) {}
  ~Toolhelp32Snapshot() noexcept { if(snapshot_) [[likely]] CloseHandle(snapshot_); }

  operator void*() const noexcept { return snapshot_; }
 private:
  void *const snapshot_;
};

std::uint32_t GetProcessId(const std::wstring &process_name) {
  const auto snapshot = Toolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  PROCESSENTRY32W process_entry = { sizeof(PROCESSENTRY32W) };
  Process32FirstW(snapshot, &process_entry);
  do  {
    if(process_name == process_entry.szExeFile) {
      return process_entry.th32ProcessID;
    }
  } while(Process32NextW(snapshot, &process_entry));

  spdlog::error("Failed to get PID for {}", std::string(process_name.begin(), process_name.end()));
  return 0;
}

Process::Process(std::shared_ptr<Alpc> alpc, const std::wstring &process_name) :
  process_id_(GetProcessId(process_name)),
  alpc_(std::move(alpc)) {
  process_found_ = process_id_ > 0; // Advanced tech
}

} // comm