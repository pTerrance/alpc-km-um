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

#ifndef ALPCUM_SRC_MEMORY_MEMORY_H_
#define ALPCUM_SRC_MEMORY_MEMORY_H_

#include <string>
#include <expected>

#include "alpc/alpc.h"
#include "deps/mint.h"

namespace comm {

class Process {
 public:
  Process(std::shared_ptr<Alpc> alpc, const std::wstring &process_name);

  template<class T>
  auto ReadVirtualMemory(Address8Bytes auto address) const noexcept -> std::expected<T, NTSTATUS> {
    volatile T buffer{};
    NTSTATUS status = alpc_->CopyVirtual(alpc_->local_pid(), process_id_, &buffer, address, sizeof(T));
    if(!NT_SUCCESS(status)) [[unlikely]] {
      return std::unexpected(status);
    }
    return buffer;
  }

  NTSTATUS WriteVirtualMemory(Address8Bytes auto address, auto &&data) const noexcept {
    return alpc_->CopyVirtual(process_id_, alpc_->local_pid(), address, &data, sizeof(data));
  }

  bool found() const { return process_found_; }
 private:
  bool process_found_;
  std::uint32_t process_id_;
  std::shared_ptr<Alpc> alpc_;
};

} // comm

#endif //ALPCUM_SRC_MEMORY_MEMORY_H_
