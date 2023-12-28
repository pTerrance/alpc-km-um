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

#ifndef ALPCKM_SRC_ALPC_ALPC_H_
#define ALPCKM_SRC_ALPC_ALPC_H_

#include <ntdef.h>
#include "message/message.h"

namespace comm {

class Alpc {
 public:
  explicit Alpc(const wchar_t *port_name);

  [[nodiscard]] NTSTATUS CreatePort() noexcept;
  [[nodiscard]] NTSTATUS CreateListener() noexcept;

 private:
  [[nodiscard]] static NTSTATUS ClosePort(HANDLE &port) noexcept;
  [[nodiscard]] NTSTATUS CleanupClient(ApiClient* api_client) const noexcept;

  [[nodiscard]] static NTSTATUS HandleCopyVirtual(const CopyVirtual &copy_virtual) noexcept;
  [[nodiscard]] NTSTATUS HandleUnload() noexcept;
  [[nodiscard]] NTSTATUS HandleApiMessage(ApiMessage *const message) noexcept;
  [[nodiscard]] NTSTATUS HandleConnectionMessage(ApiMessage* message) noexcept;
  [[nodiscard]] NTSTATUS HandleDisconnect() noexcept;

  static void ListenerThread(Alpc *alpc) noexcept;

  bool running_ = true;
  bool connected_ = false;
  HANDLE port_handle_ = nullptr;
  UNICODE_STRING port_name_ = {};
  ApiClient* client_ = nullptr;
};

} // comm

#endif //ALPCKM_SRC_ALPC_ALPC_H_
