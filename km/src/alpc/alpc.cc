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

#include <ntifs.h>

#include "deps/phnt/ntlpcapi.h"

#include "alpc/alpc.h"
#include "logger/logger.h"
#include "utils/utils.h"

namespace comm {

Alpc::Alpc(const wchar_t *port_name) {
  if(!RtlCreateUnicodeString(&port_name_, port_name)) [[unlikely]] {
    LOG_FATAL("Failed to create port_name_.");
  }
}

NTSTATUS Alpc::CreatePort() noexcept {
  ALPC_PORT_ATTRIBUTES port_attributes{};
  port_attributes.Flags = ALPC_PORFLG_SYSTEM_PROCESS;
  port_attributes.MaxMessageLength = sizeof(ApiMessage);
  port_attributes.MemoryBandwidth = 0;
  port_attributes.MaxPoolUsage = MAXUINT32;
  port_attributes.MaxSectionSize = MAXUINT32;
  port_attributes.MaxViewSize = MAXUINT32;
  port_attributes.MaxTotalSectionSize = MAXUINT32;

  OBJECT_ATTRIBUTES object_attributes =
	  RTL_CONSTANT_OBJECT_ATTRIBUTES(&port_name_, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE);
  NTSTATUS status = ZwAlpcCreatePort(&port_handle_, &object_attributes, &port_attributes);
  if(!NT_SUCCESS(status)) [[unlikely]] {
    LOG_FATAL("Failed to create port %wZ : 0x%llx", port_name_, status);
	return status;
  }

  LOG_DEBUG("Created port %wZ", port_name_);
  return STATUS_SUCCESS;
}

NTSTATUS Alpc::ClosePort(HANDLE &port) noexcept {
  if(port == nullptr) [[unlikely]] {
    return STATUS_SUCCESS;
  }

  NTSTATUS status = ZwAlpcDisconnectPort(port, ALPC_CANCELFLG_TRY_CANCEL);
  if(!NT_SUCCESS(status)) [[unlikely]] {
    LOG_ERROR("Failed to disconnect port 0x%llx : 0x%llx", port, status);
    return status;
  }
  status = NtClose(port);
  if(!NT_SUCCESS(status)) [[unlikely]] {
    LOG_ERROR("Failed to close port 0x%llx : 0x%llx", port, status);
    return status;
  }
  port = nullptr;
  return status;
}

NTSTATUS Alpc::CleanupClient(ApiClient* api_client) const noexcept {
  LOG_DEBUG("Cleaning up client.");
  if(api_client == nullptr) [[unlikely]] {
    return STATUS_INVALID_HANDLE;
  }

  NTSTATUS status = ClosePort(api_client->port_handle);
  if(!NT_SUCCESS(status)) [[unlikely]] {
    LOG_ERROR("Failed to close client port: 0x%llx", status);
    return status;
  }

  ExFreePool(client_);
  return status;
}

NTSTATUS Alpc::CreateListener() noexcept {
  HANDLE thread_handle = nullptr;
  return PsCreateSystemThread(&thread_handle,
                              ACCESS_MASK{0},
                              nullptr,
                              nullptr,
                              nullptr,
                              reinterpret_cast<PKSTART_ROUTINE>(ListenerThread),
                              this);
}

NTSTATUS Alpc::HandleCopyVirtual(const CopyVirtual &copy_virtual) noexcept {
  PEPROCESS target_process = nullptr;
  PEPROCESS source_process = nullptr;

  // You would want to cache these, however this is just an example :)
  NTSTATUS status = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(copy_virtual.target_pid), &target_process);
  if(!NT_SUCCESS(status)) [[unlikely]] {
    LOG_ERROR("PsLookupProcessByProcessId failed with 0x%llx on pid %i.", status, copy_virtual.target_pid);
    return status;
  }

  status = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(copy_virtual.source_pid), &source_process);
  if(!NT_SUCCESS(status)) [[unlikely]] {
    LOG_ERROR("PsLookupProcessByProcessId failed with 0x%llx on pid %i.", status, copy_virtual.source_pid);
    return status;
  }

  if(!target_process || !source_process) [[unlikely]] {
    LOG_ERROR("Failed to get process for virtual memory copy.");
	return STATUS_NOT_FOUND;
  }

  SIZE_T out_size;
  status = MmCopyVirtualMemory(source_process,
                               reinterpret_cast<PVOID>(copy_virtual.source_address),
							   target_process,
							   reinterpret_cast<PVOID>(copy_virtual.target_address),
							   copy_virtual.size,
							   UserMode,
							   &out_size);

  if(!NT_SUCCESS(status) || out_size != copy_virtual.size) [[unlikely]] {
    LOG_ERROR("Failed to copy virtual memory (0x%llx, 0x%llx): 0x%lx",
			  copy_virtual.source_address,
			  copy_virtual.target_address,
			  status);
  }

  ObfDereferenceObject(source_process);
  ObfDereferenceObject(target_process);
  return status;
}

NTSTATUS Alpc::HandleUnload() noexcept {
  LOG_DEBUG("Received unload request!");
  // Thread will clean up
  running_ = false;
  return STATUS_SUCCESS;
}

NTSTATUS Alpc::HandleApiMessage(ApiMessage *const message) noexcept {
  NTSTATUS result;
  switch(message->id) {
	case MessageId::kCopyVirtual: {
	  return HandleCopyVirtual(message->data.copy_virtual);
	}
    case MessageId::kUnload: {
      return HandleUnload();
    }
  }
  LOG_ERROR("Received invalid message id %i", message->id);
  return STATUS_NOT_FOUND;
}

NTSTATUS Alpc::HandleConnectionMessage(ApiMessage* message) noexcept {
  const auto usermode_pid = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(message->header.ClientId.UniqueProcess));

  ApiClient *api_client = nullptr;
  bool accept_client = !connected_;

  if (!accept_client) [[unlikely]] {
	LOG_ERROR("Already connected, ignoring new connection from %i", usermode_pid);
  } else {
	// TODO (terry): RAII for kernel allocations.
	api_client = static_cast<ApiClient*>(ExAllocatePool(NonPagedPoolNx, sizeof(ApiClient)));
	if(api_client == nullptr) {
	  accept_client = false;
	  LOG_FATAL("Failed to accept client!");
	}
  }

  HANDLE client_port_handle = nullptr;
  NTSTATUS status = ZwAlpcAcceptConnectPort(&client_port_handle,
                                            port_handle_,
                                            0,
                                            nullptr,
                                            nullptr,
                                            api_client,
                                   &message->header,
                                   nullptr,
                                   static_cast<BOOLEAN>(accept_client));
  if(NT_SUCCESS(status)) [[likely]] {
	if(accept_client) {
	  api_client->port_handle = client_port_handle;
	}
	LOG_INFO("Successfully %hs connection.", accept_client ? "accepted" : "refused");
  } else {
	LOG_ERROR("Failed to connect to client port: 0x%llx", status);
	if(api_client != nullptr) {
	  status = CleanupClient(api_client);
      if(!NT_SUCCESS(status)) [[unlikely]] {
        LOG_ERROR("Failed to cleanup api_client: 0x%llx", status);
      }
	  return status;
	}
  }

  connected_ = true;
  return STATUS_SUCCESS;
}

NTSTATUS Alpc::HandleDisconnect() noexcept {
  LOG_INFO("Client disconnected!");
  NTSTATUS status = CleanupClient(client_);
  if(!NT_SUCCESS(status)) [[unlikely]] {
    LOG_ERROR("Failed to cleanup client: 0x%llx", status);
  }
  connected_ = false;
  return status;
}

void Alpc::ListenerThread(Alpc *const alpc) noexcept {
  LOG_DEBUG("Listener listening.");

  while(alpc->running_) {
    ApiMessage message;
    auto *const receive_message = &message;
    SIZE_T buffer_size;
    UCHAR receive_message_attributes_buffer[sizeof(ALPC_MESSAGE_ATTRIBUTES) + sizeof(ALPC_CONTEXT_ATTR) + sizeof(ALPC_DATA_VIEW_ATTR)];
    auto *receive_message_attributes = reinterpret_cast<PALPC_MESSAGE_ATTRIBUTES>(receive_message_attributes_buffer);

    NTSTATUS status = AlpcInitializeMessageAttribute(ALPC_MESSAGE_CONTEXT_ATTRIBUTE | ALPC_MESSAGE_VIEW_ATTRIBUTE,
                                   receive_message_attributes,
                                   sizeof(receive_message_attributes_buffer),
                                   &buffer_size);
    if(!NT_SUCCESS(status)) [[unlikely]] {
	  LOG_FATAL("Failed to set message attributes.");
	  return;
    }

    receive_message_attributes->ValidAttributes = ALPC_MESSAGE_CONTEXT_ATTRIBUTE | ALPC_MESSAGE_VIEW_ATTRIBUTE;
    status = ZwAlpcSendWaitReceivePort(alpc->port_handle_,
                                       0,
                                       nullptr,
                                       nullptr,
                                       &receive_message->header,
                                       nullptr,
                                       receive_message_attributes,
                                       nullptr);
	if(!NT_SUCCESS(status)) [[unlikely]] {
	  LOG_FATAL("Failed to wait on port %wZ (0x%llx)", alpc->port_name_, alpc->port_handle_);
	  return;
	}

    auto *const context_attributes = static_cast<PALPC_CONTEXT_ATTR>(AlpcGetMessageAttribute(receive_message_attributes, ALPC_MESSAGE_CONTEXT_ATTRIBUTE));
    alpc->client_ = static_cast<ApiClient*>(context_attributes->PortContext);

    const auto message_type = static_cast<LPC_TYPE>(static_cast<SHORT>(receive_message->header.u2.s2.Type) & 0xFF);
    switch (message_type) {
	  case LPC_TYPE::LPC_CONNECTION_REQUEST: {
	    receive_message->status = alpc->HandleConnectionMessage(receive_message);
		break;
	  }
	  case LPC_TYPE::LPC_REQUEST: {
	    receive_message->status = alpc->HandleApiMessage(receive_message);
	    break;
	  }
	  case LPC_TYPE::LPC_PORT_CLOSED:
	  case LPC_TYPE::LPC_CLIENT_DIED: {
	    receive_message->status = alpc->HandleDisconnect();
		break;
	  }
	  default: {
	    LOG_ERROR("Unhandled message type: %i", message_type);
	  }
	}

    const bool requires_response = (static_cast<std::int16_t>(receive_message->header.u2.s2.Type) & LPC_CONTINUATION_REQUIRED) != 0;

	// Respond if required (sync argument in Send)
    if (message_type == LPC_TYPE::LPC_REQUEST && requires_response) [[likely]] {
	  if (receive_message_attributes->ValidAttributes & ALPC_MESSAGE_VIEW_ATTRIBUTE) {
	    auto *const data_view = static_cast<PALPC_DATA_VIEW_ATTR>(AlpcGetMessageAttribute(receive_message_attributes, ALPC_MESSAGE_VIEW_ATTRIBUTE));
	    if (data_view != nullptr && data_view->ViewBase != nullptr) {
	      ZwAlpcDeleteSectionView(alpc->port_handle_, 0, data_view->ViewBase);
	    }
	  }

	  status = ZwAlpcSendWaitReceivePort(alpc->port_handle_,
                                         ALPC_MSGFLG_RELEASE_MESSAGE,
                                         &receive_message->header,
	                                     nullptr,
                                         nullptr,
                                         nullptr,
                                         nullptr,
                                         nullptr);
	  if (!NT_SUCCESS(status)) [[unlikely]] {
	    LOG_ERROR("Unable to process message, (ZwAlpcSendWaitReceivePort): 0x%llx", status);
	    status = alpc->HandleDisconnect();
        if (!NT_SUCCESS(status)) [[unlikely]] {
          LOG_ERROR("Unable to disconnect client: 0x%llx", status);
        }
	    continue;
	  }
    }
  }

  NTSTATUS status = ClosePort(alpc->port_handle_);
  if(!NT_SUCCESS(status)) [[unlikely]] {
    LOG_ERROR("Failed to close port on cleanup.");
  }
  ExFreePool(alpc);
  LOG_INFO("Unloaded.");
}

} // comm