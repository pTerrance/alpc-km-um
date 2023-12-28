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

#include "alpc.h"

#include "spdlog/spdlog.h"

namespace comm {

Alpc::Alpc(const std::wstring &port_name) : local_pid_(GetCurrentProcessId()) {
  if (!RtlCreateUnicodeString(&port_name_, port_name.data())) {
	spdlog::critical("Unable to create unicode string for {}", std::string(port_name.begin(), port_name.end()));
  }
}

Alpc::~Alpc() {
  NtAlpcDisconnectPort(port_handle_, 0);
  NtClose(port_handle_);
}

bool Alpc::ConnectPort() noexcept {
  constexpr auto kTotalMessageSize = sizeof(ApiMessage);

  SECURITY_QUALITY_OF_SERVICE qos;
  RtlZeroMemory(&qos, sizeof(SECURITY_QUALITY_OF_SERVICE));
  qos.Length = sizeof(qos);
  qos.ImpersonationLevel = SecurityImpersonation;
  qos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
  qos.EffectiveOnly = true;

  ALPC_PORT_ATTRIBUTES port_attributes;
  RtlZeroMemory(&port_attributes, sizeof(ALPC_PORT_ATTRIBUTES));
  port_attributes.Flags = 0x10000; // ALPC_PORFLG_CAN_IMPERSONATE
  port_attributes.MaxMessageLength = kTotalMessageSize;
  port_attributes.SecurityQos = qos;

  auto connection_message = std::make_unique<ApiMessage>();
  InitMessage(connection_message, kTotalMessageSize);
  const auto status = NtAlpcConnectPort(&port_handle_,
                                        &port_name_,
                                        nullptr,
                                        &port_attributes,
                                        0,
                                        nullptr,
                                        &connection_message->header,
                                        nullptr,
                                        nullptr,
                                        nullptr,
                                        nullptr);
  if (!NT_SUCCESS(status)) {
    std::wstring port(port_name_.Buffer);
	spdlog::critical("Unable to connect, to {}: {:X}",
                     std::string(port.begin(), port.end()),
                     static_cast<std::uint32_t>(status));
	return false;
  }

  return true;
}

std::unique_ptr<ApiMessage> Alpc::CreateMessage() const noexcept {
  auto message = std::make_unique<ApiMessage>();
  InitMessage(message, sizeof(ApiMessage));
  return std::move(message);
}

NTSTATUS Alpc::Send(const std::unique_ptr<ApiMessage> &message, bool sync) const noexcept {
  NTSTATUS status = NtAlpcSendWaitReceivePort(port_handle_,
											  sync ? ALPC_MSGFLG_SYNC_REQUEST : 0,
                                              &message->header,
                                              nullptr,
                                              &message->header,
                                              nullptr,
                                              nullptr,
                                              nullptr);
  if (!NT_SUCCESS(status)) {
	spdlog::error("Unable to send message, (NtAlpcSendWaitReceivePort): {:X}", static_cast<std::uint32_t>(status));
	return status;
  }
  return STATUS_SUCCESS;
}

NTSTATUS Alpc::Unload() const noexcept {
  auto message = std::make_unique<ApiMessage>();
  message->id = MessageId::kUnload;
  return Send(message);
}

void Alpc::InitMessage(const std::unique_ptr<ApiMessage> &message, const std::size_t total_message_length) noexcept {
  const auto data_length = static_cast<SHORT>(total_message_length - sizeof(PORT_MESSAGE));
  message->header.u1.s1.TotalLength = static_cast<SHORT>(total_message_length);
  message->header.u1.s1.DataLength = data_length;
}


} // comm