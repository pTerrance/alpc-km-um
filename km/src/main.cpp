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

#include <wdm.h>

#include "alpc/alpc.h"

#include "utils/utils.h"
#include "logger/logger.h"

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT /*driverObject*/, PUNICODE_STRING /*registryPath*/) noexcept {
  LOG_DEBUG("Driver loaded");

  auto *const alpc = new comm::Alpc(LR"(\RPC Control\ExampleAlpcDriver)");
  NTSTATUS status = alpc->CreatePort();
  if (!NT_SUCCESS(status)) [[unlikely]] {
	LOG_FATAL("Failed to create port!");
	return status;
  }

  status = alpc->CreateListener();
  if (!NT_SUCCESS(status)) [[unlikely]] {
	LOG_FATAL("Failed to create listener!");
	return status;
  }

  LOG_INFO("Successfully loaded, exiting now.");
  return STATUS_SUCCESS;
}