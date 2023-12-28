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

#ifndef ALPCUM_SRC_ALPC_MESSAGE_MESSAGE_H_
#define ALPCUM_SRC_ALPC_MESSAGE_MESSAGE_H_

#include <cstdint>

#include "deps/mint.h"

enum class MessageId : std::uint8_t {
  kCopyVirtual,
  kUnload
};

struct CopyVirtual {
  std::uint32_t source_pid;
  std::uintptr_t source_address;
  std::uint32_t target_pid;
  std::uintptr_t target_address;
  std::uint32_t size;
};

struct ApiClient {
  HANDLE port_handle;
  ALPC_DATA_VIEW_ATTR data_view;
};

struct ApiMessage {
  ApiMessage() { std::memset(this, 0x0, sizeof(*this)); }

  PORT_MESSAGE header;
  union {
	struct {
	  MessageId id;
	  NTSTATUS status;
	  union {
	    CopyVirtual copy_virtual;
	  } data;
	};
  };
};

static_assert(sizeof(ApiMessage) <= PORT_TOTAL_MAXIMUM_MESSAGE_LENGTH, "Message too big!");

#endif //ALPCUM_SRC_ALPC_MESSAGE_MESSAGE_H_
