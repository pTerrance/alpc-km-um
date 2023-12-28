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

#ifndef ALPCUM_SRC_ALPC_ALPC_H_
#define ALPCUM_SRC_ALPC_ALPC_H_

#include <string>
#include <memory>

#include "deps/mint.h"

#include "alpc/message/message.h"

namespace comm {

template<class T>
concept Address8Bytes = sizeof(T) == 8;

class Alpc {
 public:
  explicit Alpc(const std::wstring &port_name);
  ~Alpc();

  [[nodiscard]] bool ConnectPort() noexcept;
  [[nodiscard]] NTSTATUS Send(const std::unique_ptr<ApiMessage> &message, bool sync = true) const noexcept;
  [[nodiscard]] std::unique_ptr<ApiMessage> CreateMessage() const noexcept;

  [[nodiscard]] NTSTATUS Unload() const noexcept;
  [[nodiscard]] NTSTATUS CopyVirtual(const std::uint32_t target_pid,
                                     const std::uint32_t source_pid,
                                     const Address8Bytes auto target_address,
                                     const Address8Bytes auto source_address,
                                     const std::uint32_t size) const noexcept {
    auto message = CreateMessage();
    message->id = MessageId::kCopyVirtual;
    message->data.copy_virtual.target_pid = target_pid;
    message->data.copy_virtual.source_pid = source_pid;
    message->data.copy_virtual.target_address = std::uintptr_t(target_address);
    message->data.copy_virtual.source_address = std::uintptr_t(source_address);
    message->data.copy_virtual.size = size;
    return Send(message);
  }

  [[nodiscard]] std::uint32_t local_pid() const noexcept { return local_pid_; }

 private:
  static void InitMessage(const std::unique_ptr<ApiMessage> &message, std::size_t total_message_length) noexcept;

  std::uint32_t local_pid_;
  HANDLE port_handle_;
  UNICODE_STRING port_name_;
};

} // comm

#endif //ALPCUM_SRC_ALPC_ALPC_H_
