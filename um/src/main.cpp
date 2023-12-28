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

#include <random>

#include "spdlog/spdlog.h"

#include "memory/memory.h"

struct PauseOnExit {
  ~PauseOnExit() {
    std::getchar();
  }
};

int main() {
  PauseOnExit _{}; // :upside_down:
  using namespace std::chrono_literals;

  auto alpc = std::make_shared<comm::Alpc>(LR"(\RPC Control\ExampleAlpcDriver)");
  if (!alpc->ConnectPort()) [[unlikely]] {
    spdlog::critical("Failed to connect. Make sure the driver is loaded.");
    return STATUS_NOT_FOUND;
  }

  spdlog::info("Connected!");

  const std::wstring target_process_name = L"example.exe";
  comm::Process target(alpc, target_process_name);
  if(!target.found()) [[unlikely]] {
    spdlog::error("{} not found.", std::string(target_process_name.begin(), target_process_name.end()));
    return STATUS_NOT_FOUND;
  }

  // Allow time for the port to be able to start to accept messages
  std::this_thread::sleep_for(2s);

  // Quick example reading and writing to an address
  static constexpr std::uintptr_t kAddr = 0xae43cff730;
  const auto read_result = target.ReadVirtualMemory<int>(kAddr);
  if (!read_result) [[unlikely]] {
    spdlog::error("Failed to read virtual memory: {:X}", read_result.error());
  } else {
    spdlog::info("Read value: {}", read_result.value());
  }

  std::mt19937 gen(std::random_device{}());
  target.WriteVirtualMemory(kAddr, std::uniform_int_distribution<>{}(gen));

  spdlog::info("Press F2 to unload to driver.");
  while(true) {
    if(GetAsyncKeyState(VK_F2) & 1) {
      NTSTATUS status = alpc->Unload();
      if(!NT_SUCCESS(status)) {
        spdlog::error("Failed to unload driver: {:X}", static_cast<std::uint32_t>(status));
      } else {
        spdlog::info("Successfully unloaded driver!");
      }
      break;
    }
    std::this_thread::sleep_for(50ms);
  }

  return STATUS_SUCCESS;
}