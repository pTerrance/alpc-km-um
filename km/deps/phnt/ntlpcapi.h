#pragma once

/*
 * Windows NT LPC and ALPC declarations
 */

#ifdef __cplusplus
extern "C" {
#endif

	// Local Inter-process Communication

#define PORT_CONNECT 0x0001
#define PORT_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1)

#ifdef _KERNEL_MODE
	extern POBJECT_TYPE LpcPortObjectType;
#endif

#if defined(__cplusplus)
#if ((defined(_MSC_VER) && (_MSC_VER >= 1700)) || \
	defined(__clang__))
	enum class LPC_TYPE : SHORT
	{
#else
	typedef enum _LPC_TYPE : SHORT
	{
#endif
		LPC_NEW_MESSAGE = 0,
		LPC_REQUEST = 1,
		LPC_REPLY = 2,
		LPC_DATAGRAM = 3,
		LPC_LOST_REPLY = 4,
		LPC_PORT_CLOSED = 5,
		LPC_CLIENT_DIED = 6,
		LPC_EXCEPTION = 7,
		LPC_DEBUG_EVENT = 8,
		LPC_ERROR_EVENT = 9,
		LPC_CONNECTION_REQUEST = 10,
		LPC_UNKNOWN = 11,
		LPC_RUMP_MESSAGE = 12,
		LPC_MAXIMUM
#if ((defined(_MSC_VER) && (_MSC_VER >= 1700)) || \
	defined(__clang__))
	};
#else
	} LPC_TYPE;
#endif
#else
#define LPC_REQUEST				1
#define LPC_REPLY				2
#define LPC_DATAGRAM			3
#define LPC_LOST_REPLY			4
#define LPC_PORT_CLOSED			5
#define LPC_CLIENT_DIED			6
#define LPC_EXCEPTION			7
#define LPC_DEBUG_EVENT			8
#define LPC_ERROR_EVENT			9
#define LPC_CONNECTION_REQUEST	10
#define LPC_UNKNOWN				11
#define LPC_RUMP_MESSAGE		12
	typedef SHORT LPC_TYPE;
#endif

#define LPC_KERNELMODE_MESSAGE		((SHORT)0x8000)
#define LPC_NO_IMPERSONATE			((SHORT)0x4000)
#define LPC_CONTINUATION_REQUIRED	((SHORT)0x2000) // Indicates a message must be either replied to or cancelled

#define PORT_VALID_OBJECT_ATTRIBUTES OBJ_CASE_INSENSITIVE

	// 32/64 bit compatibility. 32 bit programs must use 64 bit types under WoW64. #define USE_LPC6432 to enable this.
#if !defined(_WIN64) && defined(USE_LPC6432)
	typedef struct _CLIENT_ID64 { PVOID64 UniqueProcess; PVOID64 UniqueThread; } CLIENT_ID64;
	typedef CLIENT_ID64 LPC_CLIENT_ID, * PLPC_CLIENT_ID;
	typedef ULONG64 LPC_SIZE_T, * PLPC_SIZE_T;
	typedef PVOID64 LPC_PVOID, * PLPC_PVOID;
	typedef PVOID64 LPC_HANDLE, * PLPC_HANDLE;
#else
	typedef CLIENT_ID LPC_CLIENT_ID, * PLPC_CLIENT_ID;
	typedef SIZE_T LPC_SIZE_T, * PLPC_SIZE_T;
	typedef PVOID LPC_PVOID, * PLPC_PVOID;
	typedef HANDLE LPC_HANDLE, * PLPC_HANDLE;
#endif

	typedef struct _PORT_MESSAGE
	{
		union
		{
			struct
			{
				SHORT DataLength;
				SHORT TotalLength;
			} s1;
			ULONG Length;
		} u1;
		union
		{
			struct
			{
				LPC_TYPE Type;
				SHORT DataInfoOffset;
			} s2;
			ULONG ZeroInit;
		} u2;
		union
		{
			LPC_CLIENT_ID ClientId;
			double DoNotUseThisField;
		};
		ULONG MessageId;
		union
		{
			LPC_SIZE_T ClientViewSize; // only valid for LPC_CONNECTION_REQUEST messages
			ULONG CallbackId; // only valid for LPC_REQUEST messages
		};
	} PORT_MESSAGE, * PPORT_MESSAGE;

	// Maximum message length
#define PORT_TOTAL_MAXIMUM_MESSAGE_LENGTH 0xFFFF

	typedef struct _PORT_VIEW
	{
		ULONG Length;
		LPC_HANDLE SectionHandle;
		ULONG SectionOffset;
		LPC_SIZE_T ViewSize;
		LPC_PVOID ViewBase;
		LPC_PVOID ViewRemoteBase;
	} PORT_VIEW, * PPORT_VIEW;

	typedef struct _ALPC_PORT_CALLBACK_INFORMATION
	{
		struct _CALLBACK_OBJECT* CallbackObject;
		PVOID Context;
	} ALPC_PORT_CALLBACK_INFORMATION, * PALPC_PORT_CALLBACK_INFORMATION;

	typedef struct _REMOTE_PORT_VIEW
	{
		ULONG Length;
		LPC_SIZE_T ViewSize;
		LPC_PVOID ViewBase;
	} REMOTE_PORT_VIEW, * PREMOTE_PORT_VIEW;

	typedef struct _LPC_CLIENT_DIED_MSG
	{
		PORT_MESSAGE PortMsg;
		LARGE_INTEGER CreateTime;
	} LPC_CLIENT_DIED_MSG, * PLPC_CLIENT_DIED_MSG;


	// Port creation

#ifndef _KERNEL_MODE
	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtCreatePort(
			_Out_ PHANDLE PortHandle,
			_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
			_In_ ULONG MaxConnectionInfoLength,
			_In_ ULONG MaxMessageLength,
			_In_opt_ ULONG MaxPoolUsage
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtCreateWaitablePort(
			_Out_ PHANDLE PortHandle,
			_In_ POBJECT_ATTRIBUTES ObjectAttributes,
			_In_opt_ ULONG MaxConnectionInfoLength,
			_In_ ULONG MaxMessageLength,
			_In_opt_ ULONG MaxPoolUsage
		);
#endif

	// Port connection (client)

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtConnectPort(
			_Out_ PHANDLE PortHandle,
			_In_ PUNICODE_STRING PortName,
			_In_ PSECURITY_QUALITY_OF_SERVICE SecurityQos,
			_Inout_opt_ PPORT_VIEW ClientView,
			_Inout_opt_ PREMOTE_PORT_VIEW ServerView,
			_Out_opt_ PULONG MaxMessageLength,
			_Inout_updates_bytes_to_opt_(*ConnectionInformationLength, *ConnectionInformationLength) PVOID ConnectionInformation,
			_Inout_opt_ PULONG ConnectionInformationLength
		);

#ifdef _KERNEL_MODE
	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSYSCALLAPI
		NTSTATUS
		NTAPI
		ZwConnectPort(
			_Out_ PHANDLE PortHandle,
			_In_ PUNICODE_STRING PortName,
			_In_ PSECURITY_QUALITY_OF_SERVICE SecurityQos,
			_Inout_opt_ PPORT_VIEW ClientView,
			_Inout_opt_ PREMOTE_PORT_VIEW ServerView,
			_Out_opt_ PULONG MaxMessageLength,
			_Inout_updates_bytes_to_opt_(*ConnectionInformationLength, *ConnectionInformationLength) PVOID ConnectionInformation,
			_Inout_opt_ PULONG ConnectionInformationLength
		);
#endif

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtSecureConnectPort(
			_Out_ PHANDLE PortHandle,
			_In_ PUNICODE_STRING PortName,
			_In_ PSECURITY_QUALITY_OF_SERVICE SecurityQos,
			_Inout_opt_ PPORT_VIEW ClientView,
			_In_opt_ PSID RequiredServerSid,
			_Inout_opt_ PREMOTE_PORT_VIEW ServerView,
			_Out_opt_ PULONG MaxMessageLength,
			_Inout_updates_bytes_to_opt_(*ConnectionInformationLength, *ConnectionInformationLength) PVOID ConnectionInformation,
			_Inout_opt_ PULONG ConnectionInformationLength
		);

#ifdef _KERNEL_MODE
	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSYSCALLAPI
		NTSTATUS
		NTAPI
		ZwSecureConnectPort(
			_Out_ PHANDLE PortHandle,
			_In_ PUNICODE_STRING PortName,
			_In_ PSECURITY_QUALITY_OF_SERVICE SecurityQos,
			_Inout_opt_ PPORT_VIEW ClientView,
			_In_opt_ PSID RequiredServerSid,
			_Inout_opt_ PREMOTE_PORT_VIEW ServerView,
			_Out_opt_ PULONG MaxMessageLength,
			_Inout_updates_bytes_to_opt_(*ConnectionInformationLength, *ConnectionInformationLength) PVOID ConnectionInformation,
			_Inout_opt_ PULONG ConnectionInformationLength
		);
#endif

	// Port connection (server)

#ifndef _KERNEL_MODE
	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtListenPort(
			_In_ HANDLE PortHandle,
			_Out_ PPORT_MESSAGE ConnectionRequest
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAcceptConnectPort(
			_Out_ PHANDLE PortHandle,
			_In_opt_ PVOID PortContext,
			_In_ PPORT_MESSAGE ConnectionRequest,
			_In_ BOOLEAN AcceptConnection,
			_Inout_opt_ PPORT_VIEW ServerView,
			_Out_opt_ PREMOTE_PORT_VIEW ClientView
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtCompleteConnectPort(
			_In_ HANDLE PortHandle
		);
#endif

	// General

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtRequestPort(
			_In_ HANDLE PortHandle,
			_In_reads_bytes_(RequestMessage->u1.s1.TotalLength) PPORT_MESSAGE RequestMessage
		);

#ifdef _KERNEL_MODE
	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSYSAPI
		NTSTATUS
		NTAPI
		LpcRequestPort(
			_In_ PVOID PortAddress,
			_In_reads_bytes_(RequestMessage->u1.s1.TotalLength) PPORT_MESSAGE RequestMessage
		);

	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSYSCALLAPI
		NTSTATUS
		NTAPI
		ZwRequestPort(
			_In_ HANDLE PortHandle,
			_In_reads_bytes_(RequestMessage->u1.s1.TotalLength) PPORT_MESSAGE RequestMessage
		);
#endif

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtRequestWaitReplyPort(
			_In_ HANDLE PortHandle,
			_In_reads_bytes_(RequestMessage->u1.s1.TotalLength) PPORT_MESSAGE RequestMessage,
			_Out_ PPORT_MESSAGE ReplyMessage
		);

#ifdef _KERNEL_MODE
	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSYSAPI
		NTSTATUS
		NTAPI
		LpcRequestWaitReplyPort(
			_In_ PVOID PortAddress,
			_In_reads_bytes_(RequestMessage->u1.s1.TotalLength) PPORT_MESSAGE RequestMessage,
			_Out_ PPORT_MESSAGE ReplyMessage
		);

	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSYSCALLAPI
		NTSTATUS
		NTAPI
		ZwRequestWaitReplyPort(
			_In_ HANDLE PortHandle,
			_In_reads_bytes_(RequestMessage->u1.s1.TotalLength) PPORT_MESSAGE RequestMessage,
			_Out_ PPORT_MESSAGE ReplyMessage
		);
#endif

#ifndef _KERNEL_MODE
	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtReplyPort(
			_In_ HANDLE PortHandle,
			_In_reads_bytes_(ReplyMessage->u1.s1.TotalLength) PPORT_MESSAGE ReplyMessage
		);
#endif

#ifndef _KERNEL_MODE
	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtReplyWaitReplyPort(
			_In_ HANDLE PortHandle,
			_Inout_ PPORT_MESSAGE ReplyMessage
		);
#elif NTDDI_VERSION >= NTDDI_VISTA
	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSYSAPI
		NTSTATUS
		NTAPI
		LpcReplyWaitReplyPort(
			_In_ PVOID PortAddress,
			_In_reads_bytes_(ReplyMessage->u1.s1.TotalLength) _Out_ PPORT_MESSAGE ReplyMessage
		);
#endif

	typedef enum _PORT_INFORMATION_CLASS
	{
		PortBasicInformation,
		PortDumpInformation
	} PORT_INFORMATION_CLASS;

#ifndef _KERNEL_MODE
	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtReplyWaitReceivePort(
			_In_ HANDLE PortHandle,
			_Out_opt_ PVOID* PortContext,
			_In_reads_bytes_opt_(ReplyMessage->u1.s1.TotalLength) PPORT_MESSAGE ReplyMessage,
			_Out_ PPORT_MESSAGE ReceiveMessage
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtReplyWaitReceivePortEx(
			_In_ HANDLE PortHandle,
			_Out_opt_ PVOID* PortContext,
			_In_reads_bytes_opt_(ReplyMessage->u1.s1.TotalLength) PPORT_MESSAGE ReplyMessage,
			_Out_ PPORT_MESSAGE ReceiveMessage,
			_In_opt_ PLARGE_INTEGER Timeout
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtImpersonateClientOfPort(
			_In_ HANDLE PortHandle,
			_In_ PPORT_MESSAGE Message
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtReadRequestData(
			_In_ HANDLE PortHandle,
			_In_ PPORT_MESSAGE Message,
			_In_ ULONG DataEntryIndex,
			_Out_writes_bytes_to_(BufferSize, *NumberOfBytesRead) PVOID Buffer,
			_In_ SIZE_T BufferSize,
			_Out_opt_ PSIZE_T NumberOfBytesRead
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtWriteRequestData(
			_In_ HANDLE PortHandle,
			_In_ PPORT_MESSAGE Message,
			_In_ ULONG DataEntryIndex,
			_In_reads_bytes_(BufferSize) PVOID Buffer,
			_In_ SIZE_T BufferSize,
			_Out_opt_ PSIZE_T NumberOfBytesWritten
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtQueryInformationPort(
			_In_opt_ HANDLE PortHandle,
			_In_ PORT_INFORMATION_CLASS PortInformationClass,
			_Out_writes_bytes_to_(Length, *ReturnLength) PVOID PortInformation,
			_In_ ULONG Length,
			_Out_opt_ PULONG ReturnLength
		);
#endif

	// Asynchronous Local Inter-process Communication

	typedef HANDLE ALPC_HANDLE, * PALPC_HANDLE;

	// Additional untested flags, taken from 'Windows Privilege Escalation Through LPC and ALPC Interfaces' (Thomas Garnier):
#define ALPC_PORFLG_LPCMODE 0x1000						// Behave like an LPC port
#define ALPC_PORFLG_CAN_IMPERSONATE 0x10000				// Accept impersonation by server
#define ALPC_PORFLG_HANDLE_EXPOSE 0x80000				// Accept handle expose // ?

// Process Hacker flags
#define ALPC_PORFLG_ALLOW_LPC_REQUESTS 0x20000
#define ALPC_PORFLG_WAITABLE_PORT 0x40000
#define ALPC_PORFLG_SYSTEM_PROCESS 0x100000				// Kernel mode callers must set this on port creation

#define ALPC_OBJTYPE_SYNC 0x2
#define ALPC_OBJTYPE_THREAD 0x4

	typedef struct _ALPC_PORT_ATTRIBUTES
	{
		ULONG Flags;
		SECURITY_QUALITY_OF_SERVICE SecurityQos;
		SIZE_T MaxMessageLength;
		SIZE_T MemoryBandwidth;
		SIZE_T MaxPoolUsage;
		SIZE_T MaxSectionSize;
		SIZE_T MaxViewSize;
		SIZE_T MaxTotalSectionSize;
		ULONG DupObjectTypes;
#ifdef _WIN64
		ULONG Reserved;
#endif
	} ALPC_PORT_ATTRIBUTES, * PALPC_PORT_ATTRIBUTES;

#define ALPC_MESSAGE_SECURITY_ATTRIBUTE			0x80000000
#define ALPC_MESSAGE_VIEW_ATTRIBUTE				0x40000000
#define ALPC_MESSAGE_CONTEXT_ATTRIBUTE			0x20000000
#define ALPC_MESSAGE_HANDLE_ATTRIBUTE			0x10000000
#define ALPC_MESSAGE_TOKEN_ATTRIBUTE			0x8000000
#define ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE	0x2000000

	typedef struct _ALPC_MESSAGE_ATTRIBUTES
	{
		ULONG AllocatedAttributes;
		ULONG ValidAttributes;
	} ALPC_MESSAGE_ATTRIBUTES, * PALPC_MESSAGE_ATTRIBUTES;

	typedef struct _ALPC_WORK_ON_BEHALF_TICKET
	{
		ULONG ThreadId;
		ULONG ThreadCreationTimeLow;
	} ALPC_WORK_ON_BEHALF_TICKET, * PALPC_WORK_ON_BEHALF_TICKET;

	typedef struct _ALPC_COMPLETION_LIST_STATE
	{
		union
		{
			struct
			{
				ULONG64 Head : 24;
				ULONG64 Tail : 24;
				ULONG64 ActiveThreadCount : 16;
			} s1;
			ULONG64 Value;
		} u1;
	} ALPC_COMPLETION_LIST_STATE, * PALPC_COMPLETION_LIST_STATE;

#define ALPC_COMPLETION_LIST_BUFFER_GRANULARITY_MASK 0x3f

#ifdef _KERNEL_MODE
	// In kernel mode, use a pushlock instead of an SRW lock. They have the same struct layout

#ifdef EX_PUSH_LOCK // ntifs.h is guilty of this
#undef EX_PUSH_LOCK
#undef PEX_PUSH_LOCK
#endif

	typedef struct _EX_PUSH_LOCK
	{
		union
		{
			struct
			{
				ULONG_PTR Locked : 1;
				ULONG_PTR Waiting : 1;
				ULONG_PTR Waking : 1;
				ULONG_PTR MultipleShared : 1;
				ULONG_PTR Shared : sizeof(ULONG_PTR) * 8 - 4;
			};
			__volatile ULONG_PTR Value;
			__volatile PVOID Ptr;
		};
	} EX_PUSH_LOCK, * PEX_PUSH_LOCK;

	typedef EX_PUSH_LOCK RTL_SRWLOCK, * PRTL_SRWLOCK;
#endif

	// !!!ACHTUNG!!! Windows 8 has changed this alignment and thus the size of ALPC_COMPLETION_LIST_HEADER.
#define COMPLETION_LIST_ALIGN_VISTA	128
#define COMPLETION_LIST_ALIGN_8		64

	typedef struct DECLSPEC_ALIGN(COMPLETION_LIST_ALIGN_VISTA) _ALPC_COMPLETION_LIST_HEADER_VISTA
	{
		ULONG64 StartMagic;

		ULONG TotalSize;
		ULONG ListOffset;
		ULONG ListSize;
		ULONG BitmapOffset;
		ULONG BitmapSize;
		ULONG DataOffset;
		ULONG DataSize;
		ULONG AttributeFlags;
		ULONG AttributeSize;

		DECLSPEC_ALIGN(COMPLETION_LIST_ALIGN_VISTA) ALPC_COMPLETION_LIST_STATE State;
		volatile ULONG LastMessageId;
		volatile ULONG LastCallbackId;
		DECLSPEC_ALIGN(COMPLETION_LIST_ALIGN_VISTA) volatile ULONG PostCount;
		DECLSPEC_ALIGN(COMPLETION_LIST_ALIGN_VISTA) volatile ULONG ReturnCount;
		DECLSPEC_ALIGN(COMPLETION_LIST_ALIGN_VISTA) volatile ULONG LogSequenceNumber;
		DECLSPEC_ALIGN(COMPLETION_LIST_ALIGN_VISTA) RTL_SRWLOCK UserLock;

		ULONG64 EndMagic;
	} ALPC_COMPLETION_LIST_HEADER_VISTA;

	typedef struct DECLSPEC_ALIGN(COMPLETION_LIST_ALIGN_8) _ALPC_COMPLETION_LIST_HEADER_8
	{
		ULONG64 StartMagic;

		ULONG TotalSize;
		ULONG ListOffset;
		ULONG ListSize;
		ULONG BitmapOffset;
		ULONG BitmapSize;
		ULONG DataOffset;
		ULONG DataSize;
		ULONG AttributeFlags;
		ULONG AttributeSize;

		DECLSPEC_ALIGN(COMPLETION_LIST_ALIGN_8) ALPC_COMPLETION_LIST_STATE State;
		volatile ULONG LastMessageId;
		volatile ULONG LastCallbackId;
		DECLSPEC_ALIGN(COMPLETION_LIST_ALIGN_8) volatile ULONG PostCount;
		DECLSPEC_ALIGN(COMPLETION_LIST_ALIGN_8) volatile ULONG ReturnCount;
		DECLSPEC_ALIGN(COMPLETION_LIST_ALIGN_8) volatile ULONG LogSequenceNumber;
		DECLSPEC_ALIGN(COMPLETION_LIST_ALIGN_8) RTL_SRWLOCK UserLock;

		ULONG64 EndMagic;
	} ALPC_COMPLETION_LIST_HEADER_8;

#if NTDDI_VERSION >= NTDDI_WIN8
	typedef ALPC_COMPLETION_LIST_HEADER_8 ALPC_COMPLETION_LIST_HEADER, * PALPC_COMPLETION_LIST_HEADER;
#else
	typedef ALPC_COMPLETION_LIST_HEADER_VISTA ALPC_COMPLETION_LIST_HEADER, * PALPC_COMPLETION_LIST_HEADER;
#endif

#if NTDDI_VERSION >= NTDDI_WIN10
	typedef union _KALPC_DIRECT_EVENT
	{
		UCHAR Event;
		ULONG_PTR Referenced : 1;
		ULONG_PTR Reserved : sizeof(ULONG_PTR) * 8 - 1;
	} KALPC_DIRECT_EVENT;
#endif

	typedef struct _ALPC_DISPATCH_CONTEXT
	{
		PVOID PortObject;
		PVOID Message;
		PVOID CommunicationInfo;
#if NTDDI_VERSION >= NTDDI_WIN7
		struct _ETHREAD* TargetThread;
		PVOID TargetPort;
#endif
#if NTDDI_VERSION >= NTDDI_WIN10
		KALPC_DIRECT_EVENT DirectEvent;
#endif
		ULONG Flags;
		USHORT TotalLength;
		USHORT Type;
		USHORT DataInfoOffset;
#if NTDDI_VERSION >= NTDDI_WIN8
		UCHAR SignalCompletion;
		UCHAR PostedToCompletionList;
#endif
	} ALPC_DISPATCH_CONTEXT, * PALPC_DISPATCH_CONTEXT;

	typedef struct _ALPC_CONTEXT_ATTR
	{
		PVOID PortContext;
		PVOID MessageContext;
		ULONG Sequence;
		ULONG MessageId;
		ULONG CallbackId;
	} ALPC_CONTEXT_ATTR, * PALPC_CONTEXT_ATTR;

#define ALPC_HANDLEFLG_DUPLICATE_SAME_ACCESS 0x10000
#define ALPC_HANDLEFLG_DUPLICATE_SAME_ATTRIBUTES 0x20000
#define ALPC_HANDLEFLG_DUPLICATE_INHERIT 0x80000

	typedef struct _ALPC_HANDLE_ATTR32
	{
		union
		{
			struct
			{
				ULONG Reserved0 : 16;
				ULONG SameAccess : 1;
				ULONG SameAttributes : 1;
				ULONG Indirect : 1;
				ULONG Inherit : 1;
				ULONG Reserved1 : 12;
			};
			ULONG Flags;
		};
		ULONG Handle;
		ULONG ObjectType; // ObjectTypeCode, not ObjectTypeIndex
		union
		{
			ULONG DesiredAccess;
			ULONG GrantedAccess;
		};
	} ALPC_HANDLE_ATTR32, * PALPC_HANDLE_ATTR32;

	typedef struct _ALPC_HANDLE_ATTR
	{
		union
		{
			struct
			{
				ULONG Reserved0 : 16;
				ULONG SameAccess : 1;
				ULONG SameAttributes : 1;
				ULONG Indirect : 1;
				ULONG Inherit : 1;
				ULONG Reserved1 : 12;
			};
			ULONG Flags;
		};
		union
		{
			HANDLE Handle;
			PALPC_HANDLE_ATTR32 HandleAttrArray;
		};
		union
		{
			ULONG ObjectType; // ObjectTypeCode, not ObjectTypeIndex
			ULONG HandleCount;
		};
		union
		{
			ACCESS_MASK DesiredAccess;
			ACCESS_MASK GrantedAccess;
		};
	} ALPC_HANDLE_ATTR, * PALPC_HANDLE_ATTR;

#define ALPC_SECFLG_CREATE_HANDLE 0x20000
#define ALPC_SECFLG_NOSECTIONHANDLE 0x40000

	typedef struct _ALPC_SECURITY_ATTR
	{
		ULONG Flags;
		PSECURITY_QUALITY_OF_SERVICE SecurityQoS;
		ALPC_HANDLE ContextHandle;
	} ALPC_SECURITY_ATTR, * PALPC_SECURITY_ATTR;

	typedef struct _ALPC_TOKEN_ATTR
	{
		LUID TokenId;
		LUID AuthenticationId;
		LUID ModifiedId;
	} ALPC_TOKEN_ATTR, * PALPC_TOKEN_ATTR;

	typedef struct _ALPC_WORK_ON_BEHALF_ATTR
	{
		ALPC_WORK_ON_BEHALF_TICKET Ticket;
	} ALPC_WORK_ON_BEHALF_ATTR, * PALPC_WORK_ON_BEHALF_ATTR;

#define ALPC_VIEWFLG_NOT_SECURE 0x40000
#define ALPC_VIEWFLG_AUTORELEASE 0x20000

	typedef struct _ALPC_DATA_VIEW_ATTR
	{
		ULONG Flags;
		ALPC_HANDLE SectionHandle;
		PVOID ViewBase; // Must be NULL on input
		SIZE_T ViewSize;
	} ALPC_DATA_VIEW_ATTR, * PALPC_DATA_VIEW_ATTR, ** PPALPC_DATA_VIEW_ATTR;

	typedef enum _ALPC_PORT_INFORMATION_CLASS
	{
		AlpcBasicInformation, // q: out ALPC_BASIC_INFORMATION
		AlpcPortInformation, // s: in ALPC_PORT_ATTRIBUTES
		AlpcAssociateCompletionPortInformation, // s: in ALPC_PORT_ASSOCIATE_COMPLETION_PORT
		AlpcConnectedSIDInformation, // q: in SID
		AlpcServerInformation, // q: inout ALPC_SERVER_INFORMATION
		AlpcMessageZoneInformation, // s: in ALPC_PORT_MESSAGE_ZONE_INFORMATION // no-op since 8.1
		AlpcRegisterCompletionListInformation, // s: in ALPC_PORT_COMPLETION_LIST_INFORMATION
		AlpcUnregisterCompletionListInformation, // s: VOID
		AlpcAdjustCompletionListConcurrencyCountInformation, // s: in ULONG
		AlpcRegisterCallbackInformation, // s: in ALPC_PORT_CALLBACK_INFORMATION // kernel-mode only
		AlpcCompletionListRundownInformation, // s: VOID
		AlpcWaitForPortReferences
	} ALPC_PORT_INFORMATION_CLASS;

	typedef struct _ALPC_BASIC_INFORMATION
	{
		ULONG Flags;
		ULONG SequenceNo;
		PVOID PortContext;
	} ALPC_BASIC_INFORMATION, * PALPC_BASIC_INFORMATION;

	typedef struct _ALPC_PORT_ASSOCIATE_COMPLETION_PORT
	{
		PVOID CompletionKey;
		HANDLE CompletionPort;
	} ALPC_PORT_ASSOCIATE_COMPLETION_PORT, * PALPC_PORT_ASSOCIATE_COMPLETION_PORT;

	typedef struct _ALPC_SERVER_INFORMATION
	{
		union
		{
			struct
			{
				HANDLE ThreadHandle;
			} In;

			struct
			{
				BOOLEAN ThreadBlocked;
				HANDLE ConnectedProcessId;
				UNICODE_STRING ConnectionPortName;
			} Out;
		};
	} ALPC_SERVER_INFORMATION, * PALPC_SERVER_INFORMATION;

	typedef struct _ALPC_PORT_MESSAGE_ZONE_INFORMATION
	{
		PVOID Buffer;
		SIZE_T Size;
	} ALPC_PORT_MESSAGE_ZONE_INFORMATION, * PALPC_PORT_MESSAGE_ZONE_INFORMATION;

	typedef struct _ALPC_PORT_COMPLETION_LIST_INFORMATION
	{
		PALPC_COMPLETION_LIST_HEADER Buffer;
		ULONG Size;
		ULONG ConcurrencyCount;
		ULONG AttributeFlags;
	} ALPC_PORT_COMPLETION_LIST_INFORMATION, * PALPC_PORT_COMPLETION_LIST_INFORMATION;

	typedef enum _ALPC_MESSAGE_INFORMATION_CLASS
	{
		AlpcMessageSidInformation, // q: out SID
		AlpcMessageTokenModifiedIdInformation, // q: out LUID
		AlpcMessageDirectStatusInformation,
		AlpcMessageHandleInformation, // ALPC_MESSAGE_HANDLE_INFORMATION
		MaxAlpcMessageInfoClass
	} ALPC_MESSAGE_INFORMATION_CLASS, * PALPC_MESSAGE_INFORMATION_CLASS;

	typedef struct _ALPC_MESSAGE_HANDLE_INFORMATION
	{
		ULONG Index;
		ULONG Flags;
		ULONG Handle;
		ULONG ObjectType;
		ACCESS_MASK GrantedAccess;
	} ALPC_MESSAGE_HANDLE_INFORMATION, * PALPC_MESSAGE_HANDLE_INFORMATION;

#if (NTDDI_VERSION >= NTDDI_VISTA)

	// System calls

#ifndef _KERNEL_MODE
	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		ZwAlpcCreatePort(
			_Out_ PHANDLE PortHandle,
			_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
			_In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes
		);
#else
	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSYSCALLAPI
		NTSTATUS
		NTAPI
		ZwAlpcCreatePort(
			_Out_ PHANDLE PortHandle,
			_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
			_In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes
		);
#endif

#ifndef _KERNEL_MODE
	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAlpcDisconnectPort(
			_In_ HANDLE PortHandle,
			_In_ ULONG Flags
		);
#else
	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSYSCALLAPI
		NTSTATUS
		NTAPI
		ZwAlpcDisconnectPort(
			_In_ HANDLE PortHandle,
			_In_ ULONG Flags
		);
#endif

#ifndef _KERNEL_MODE
	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAlpcQueryInformation(
			_In_opt_ HANDLE PortHandle,
			_In_ ALPC_PORT_INFORMATION_CLASS PortInformationClass,
			_Inout_updates_bytes_to_(Length, *ReturnLength) PVOID PortInformation,
			_In_ ULONG Length,
			_Out_opt_ PULONG ReturnLength
		);
#else
	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSYSCALLAPI
		NTSTATUS
		NTAPI
		ZwAlpcQueryInformation(
			_In_opt_ HANDLE PortHandle,
			_In_ __drv_strictTypeMatch(__drv_typeConst) ALPC_PORT_INFORMATION_CLASS PortInformationClass,
			_Inout_updates_bytes_to_(Length, *ReturnLength) PVOID PortInformation,
			_In_ ULONG Length,
			_Out_opt_ PULONG ReturnLength
		);
#endif

#ifndef _KERNEL_MODE
	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAlpcSetInformation(
			_In_ HANDLE PortHandle,
			_In_ ALPC_PORT_INFORMATION_CLASS PortInformationClass,
			_In_reads_bytes_opt_(Length) PVOID PortInformation,
			_In_ ULONG Length
		);
#else
	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		ZwAlpcSetInformation(
			_In_ HANDLE PortHandle,
			_In_ __drv_strictTypeMatch(__drv_typeConst) ALPC_PORT_INFORMATION_CLASS PortInformationClass,
			_In_reads_bytes_opt_(Length) PVOID PortInformation,
			_In_ ULONG Length
		);
#endif

#ifndef _KERNEL_MODE
	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAlpcCreatePortSection(
			_In_ HANDLE PortHandle,
			_In_ ULONG Flags,
			_In_opt_ HANDLE SectionHandle,
			_In_ SIZE_T SectionSize,
			_Out_ PALPC_HANDLE AlpcSectionHandle,
			_Out_ PSIZE_T ActualSectionSize
		);
#else
	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		ZwAlpcCreatePortSection(
			_In_ HANDLE PortHandle,
			_In_ ULONG Flags,
			_In_opt_ HANDLE SectionHandle,
			_In_ SIZE_T SectionSize,
			_Out_ PALPC_HANDLE AlpcSectionHandle,
			_Out_ PSIZE_T ActualSectionSize
		);
#endif

#ifndef _KERNEL_MODE
	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAlpcDeletePortSection(
			_In_ HANDLE PortHandle,
			_Reserved_ ULONG Flags,
			_In_ ALPC_HANDLE SectionHandle
		);
#else
	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSYSCALLAPI
		NTSTATUS
		NTAPI
		ZwAlpcDeletePortSection(
			_In_ HANDLE PortHandle,
			_Reserved_ ULONG Flags,
			_In_ ALPC_HANDLE SectionHandle
		);
#endif

#ifndef _KERNEL_MODE
	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAlpcCreateResourceReserve(
			_In_ HANDLE PortHandle,
			_Reserved_ ULONG Flags,
			_In_ SIZE_T MessageSize,
			_Out_ PULONG ResourceId
		);
#else
	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		ZwAlpcCreateResourceReserve(
			_In_ HANDLE PortHandle,
			_Reserved_ ULONG Flags,
			_In_ SIZE_T MessageSize,
			_Out_ PULONG ResourceId
		);
#endif

#ifndef _KERNEL_MODE
	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAlpcDeleteResourceReserve(
			_In_ HANDLE PortHandle,
			_Reserved_ ULONG Flags,
			_In_ ALPC_HANDLE ResourceId
		);
#else
	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSYSCALLAPI
		NTSTATUS
		NTAPI
		ZwAlpcDeleteResourceReserve(
			_In_ HANDLE PortHandle,
			_Reserved_ ULONG Flags,
			_In_ ALPC_HANDLE ResourceId
		);
#endif

#ifndef _KERNEL_MODE
	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAlpcCreateSectionView(
			_In_ HANDLE PortHandle,
			_Reserved_ ULONG Flags,
			_Inout_ PALPC_DATA_VIEW_ATTR ViewAttributes
		);
#else
	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSYSCALLAPI
		NTSTATUS
		NTAPI
		ZwAlpcCreateSectionView(
			_In_ HANDLE PortHandle,
			_Reserved_ ULONG Flags,
			_Inout_ PALPC_DATA_VIEW_ATTR ViewAttributes
		);
#endif

#ifndef _KERNEL_MODE
	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAlpcDeleteSectionView(
			_In_ HANDLE PortHandle,
			_Reserved_ ULONG Flags,
			_In_ PVOID ViewBase
		);
#else
	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSYSCALLAPI
		NTSTATUS
		NTAPI
		ZwAlpcDeleteSectionView(
			_In_ HANDLE PortHandle,
			_Reserved_ ULONG Flags,
			_In_ PVOID ViewBase
		);
#endif

#ifndef _KERNEL_MODE
	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAlpcCreateSecurityContext(
			_In_ HANDLE PortHandle,
			_Reserved_ ULONG Flags,
			_Inout_ PALPC_SECURITY_ATTR SecurityAttribute
		);
#else
	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSYSCALLAPI
		NTSTATUS
		NTAPI
		ZwAlpcCreateSecurityContext(
			_In_ HANDLE PortHandle,
			_Reserved_ ULONG Flags,
			_Inout_ PALPC_SECURITY_ATTR SecurityAttr
		);
#endif

#ifndef _KERNEL_MODE
	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAlpcDeleteSecurityContext(
			_In_ HANDLE PortHandle,
			_Reserved_ ULONG Flags,
			_In_ ALPC_HANDLE ContextHandle
		);
#else
	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSYSCALLAPI
		NTSTATUS
		NTAPI
		ZwAlpcDeleteSecurityContext(
			_In_ HANDLE PortHandle,
			_Reserved_ ULONG Flags,
			_In_ ALPC_HANDLE ContextHandle
		);
#endif

#ifndef _KERNEL_MODE
	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAlpcRevokeSecurityContext(
			_In_ HANDLE PortHandle,
			_Reserved_ ULONG Flags,
			_In_ ALPC_HANDLE ContextHandle
		);
#endif

#ifndef _KERNEL_MODE
	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAlpcQueryInformationMessage(
			_In_ HANDLE PortHandle,
			_In_ PPORT_MESSAGE PortMessage,
			_In_ ALPC_MESSAGE_INFORMATION_CLASS MessageInformationClass,
			_Out_writes_bytes_to_opt_(Length, *ReturnLength) PVOID MessageInformation,
			_In_ ULONG Length,
			_Out_opt_ PULONG ReturnLength
		);
#elif NTDDI_VERSION >= NTDDI_WIN10
	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSYSCALLAPI
		NTSTATUS
		NTAPI
		ZwAlpcQueryInformationMessage(
			_In_ HANDLE PortHandle,
			_In_ PPORT_MESSAGE PortMessage,
			_In_ __drv_strictTypeMatch(__drv_typeConst) ALPC_MESSAGE_INFORMATION_CLASS MessageInformationClass,
			_Out_writes_bytes_to_opt_(Length, *ReturnLength) PVOID MessageInformation,
			_In_ ULONG Length,
			_Out_opt_ PULONG ReturnLength
		);
#endif

#define ALPC_MSGFLG_REPLY_MESSAGE 0x1
#define ALPC_MSGFLG_LPC_MODE 0x2
#define ALPC_MSGFLG_RELEASE_MESSAGE 0x10000
#define ALPC_MSGFLG_SYNC_REQUEST 0x20000
#define ALPC_MSGFLG_WAIT_USER_MODE 0x100000
#define ALPC_MSGFLG_WAIT_ALERTABLE 0x200000
#define ALPC_MSGFLG_WOW64_CALL 0x80000000

#ifndef _KERNEL_MODE
	_Success_(return == 0)
		NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAlpcConnectPort(
			_Out_ PHANDLE PortHandle,
			_In_ PUNICODE_STRING PortName,
			_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
			_In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes,
			_In_ ULONG Flags,
			_In_opt_ PSID RequiredServerSid,
			_Inout_updates_bytes_to_opt_(*BufferLength, *BufferLength) PPORT_MESSAGE ConnectionMessage,
			_Inout_opt_ PSIZE_T BufferLength,
			_Inout_opt_ PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes,
			_Inout_opt_ PALPC_MESSAGE_ATTRIBUTES InMessageAttributes,
			_In_opt_ PLARGE_INTEGER Timeout
		);
#else
	_IRQL_requires_max_(PASSIVE_LEVEL)
		_Success_(return == 0)
		NTSYSCALLAPI
		NTSTATUS
		NTAPI
		ZwAlpcConnectPort(
			_Out_ PHANDLE PortHandle,
			_In_ PUNICODE_STRING PortName,
			_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
			_In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes,
			_In_ ULONG Flags,
			_In_opt_ PSID RequiredServerSid,
			_Inout_updates_bytes_to_opt_(*BufferLength, *BufferLength) PPORT_MESSAGE ConnectionMessage,
			_Inout_opt_ PSIZE_T BufferLength,
			_Inout_opt_ PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes,
			_Inout_opt_ PALPC_MESSAGE_ATTRIBUTES InMessageAttributes,
			_In_opt_ PLARGE_INTEGER Timeout
		);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN8)
#ifndef _KERNEL_MODE
	_Success_(return == 0)
		NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAlpcConnectPortEx(
			_Out_ PHANDLE PortHandle,
			_In_ POBJECT_ATTRIBUTES ConnectionPortObjectAttributes,
			_In_opt_ POBJECT_ATTRIBUTES ClientPortObjectAttributes,
			_In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes,
			_In_ ULONG Flags,
			_In_opt_ PSECURITY_DESCRIPTOR ServerSecurityRequirements,
			_Inout_updates_bytes_to_opt_(*BufferLength, *BufferLength) PPORT_MESSAGE ConnectionMessage,
			_Inout_opt_ PSIZE_T BufferLength,
			_Inout_opt_ PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes,
			_Inout_opt_ PALPC_MESSAGE_ATTRIBUTES InMessageAttributes,
			_In_opt_ PLARGE_INTEGER Timeout
		);
#else
	_IRQL_requires_max_(PASSIVE_LEVEL)
		_Success_(return == 0)
		NTSYSCALLAPI
		NTSTATUS
		NTAPI
		ZwAlpcConnectPortEx(
			_Out_ PHANDLE PortHandle,
			_In_ POBJECT_ATTRIBUTES ConnectionPortObjectAttributes,
			_In_opt_ POBJECT_ATTRIBUTES ClientPortObjectAttributes,
			_In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes,
			_In_ ULONG Flags,
			_In_opt_ PSECURITY_DESCRIPTOR ServerSecurityRequirements,
			_Inout_updates_bytes_to_opt_(*BufferLength, *BufferLength) PPORT_MESSAGE ConnectionMessage,
			_Inout_opt_ PSIZE_T BufferLength,
			_Inout_opt_ PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes,
			_Inout_opt_ PALPC_MESSAGE_ATTRIBUTES InMessageAttributes,
			_In_opt_ PLARGE_INTEGER Timeout
		);
#endif
#endif

#ifndef _KERNEL_MODE
	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAlpcAcceptConnectPort(
			_Out_ PHANDLE PortHandle,
			_In_ HANDLE ConnectionPortHandle,
			_In_ ULONG Flags,
			_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
			_In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes,
			_In_opt_ PVOID PortContext,
			_In_reads_bytes_(ConnectionRequest->u1.s1.TotalLength) PPORT_MESSAGE ConnectionRequest,
			_Inout_opt_ PALPC_MESSAGE_ATTRIBUTES ConnectionMessageAttributes,
			_In_ BOOLEAN AcceptConnection
		);
#else
	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSYSCALLAPI
		NTSTATUS
		NTAPI
		ZwAlpcAcceptConnectPort(
			_Out_ PHANDLE PortHandle,
			_In_ HANDLE ConnectionPortHandle,
			_In_ ULONG Flags,
			_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
			_In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes,
			_In_opt_ PVOID PortContext,
			_In_reads_bytes_(ConnectionRequest->u1.s1.TotalLength) PPORT_MESSAGE ConnectionRequest,
			_Inout_opt_ PALPC_MESSAGE_ATTRIBUTES ConnectionMessageAttributes,
			_In_ BOOLEAN AcceptConnection
		);
#endif

#ifndef _KERNEL_MODE
	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAlpcSendWaitReceivePort(
			_In_ HANDLE PortHandle,
			_In_ ULONG Flags,
			_In_reads_bytes_opt_(SendMessage->u1.s1.TotalLength) PPORT_MESSAGE SendMessage,
			_Inout_opt_ PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes,
			_Out_writes_bytes_to_opt_(*BufferLength, *BufferLength) PPORT_MESSAGE ReceiveMessage,
			_Inout_opt_ PSIZE_T BufferLength,
			_Inout_opt_ PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes,
			_In_opt_ PLARGE_INTEGER Timeout
		);
#else
	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSYSAPI
		NTSTATUS
		NTAPI
		LpcSendWaitReceivePort( // Can only be used for synchronous send and receive. Both messages are required
			_In_ PVOID PortAddres,
			_In_reads_bytes_(SendMessage->u1.s1.TotalLength) PPORT_MESSAGE SendMessage,
			_Inout_opt_ PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes,
			_Out_writes_bytes_to_(*BufferLength, *BufferLength) PPORT_MESSAGE ReceiveMessage,
			_Inout_opt_ PSIZE_T BufferLength,
			_Inout_opt_ PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes,
			_In_opt_ PLARGE_INTEGER Timeout
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		ZwAlpcSendWaitReceivePort(
			_In_ HANDLE PortHandle,
			_In_ ULONG Flags,
			_In_reads_bytes_opt_(SendMessage->u1.s1.TotalLength) PPORT_MESSAGE SendMessage,
			_Inout_opt_ PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes,
			_Out_writes_bytes_to_opt_(*BufferLength, *BufferLength) PPORT_MESSAGE ReceiveMessage,
			_Inout_opt_ PSIZE_T BufferLength,
			_Inout_opt_ PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes,
			_In_opt_ PLARGE_INTEGER Timeout
		);
#endif

#define ALPC_CANCELFLG_TRY_CANCEL 0x1
#define ALPC_CANCELFLG_NO_CONTEXT_CHECK 0x8
#define ALPC_CANCELFLGP_FLUSH 0x10000

#ifndef _KERNEL_MODE
	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAlpcCancelMessage(
			_In_ HANDLE PortHandle,
			_In_ ULONG Flags,
			_In_ PALPC_CONTEXT_ATTR MessageContext
		);
#else
	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSYSCALLAPI
		NTSTATUS
		NTAPI
		ZwAlpcCancelMessage(
			_In_ HANDLE PortHandle,
			_In_ ULONG Flags,
			_In_ PALPC_CONTEXT_ATTR MessageContext
		);
#endif

#ifndef _KERNEL_MODE
	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAlpcImpersonateClientOfPort(
			_In_ HANDLE PortHandle,
			_In_ PPORT_MESSAGE Message,
			_In_ PVOID Flags
		);
#endif

#if !defined(_KERNEL_MODE) && NTDDI_VERSION >= NTDDI_WIN10_TH2
	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAlpcImpersonateClientContainerOfPort(
			_In_ HANDLE PortHandle,
			_In_ PPORT_MESSAGE Message,
			_In_ ULONG Flags
		);
#endif

#ifndef _KERNEL_MODE
	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAlpcOpenSenderProcess(
			_Out_ PHANDLE ProcessHandle,
			_In_ HANDLE PortHandle,
			_In_ PPORT_MESSAGE PortMessage,
			_In_ ULONG Flags,
			_In_ ACCESS_MASK DesiredAccess,
			_In_ POBJECT_ATTRIBUTES ObjectAttributes
		);
#elif NTDDI_VERSION >= NTDDI_WIN10_RS2
	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSYSCALLAPI
		NTSTATUS
		NTAPI
		ZwAlpcOpenSenderProcess(
			_Out_ PHANDLE ProcessHandle,
			_In_ HANDLE PortHandle,
			_In_ PPORT_MESSAGE PortMessage,
			_In_ ULONG Flags,
			_In_ ACCESS_MASK DesiredAccess,
			_In_ POBJECT_ATTRIBUTES ObjectAttributes
		);
#endif

#ifndef _KERNEL_MODE
	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAlpcOpenSenderThread(
			_Out_ PHANDLE ThreadHandle,
			_In_ HANDLE PortHandle,
			_In_ PPORT_MESSAGE PortMessage,
			_In_ ULONG Flags,
			_In_ ACCESS_MASK DesiredAccess,
			_In_ POBJECT_ATTRIBUTES ObjectAttributes
		);
#elif NTDDI_VERSION >= NTDDI_WIN10
	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSYSCALLAPI
		NTSTATUS
		NTAPI
		ZwAlpcOpenSenderThread(
			_Out_ PHANDLE ThreadHandle,
			_In_ HANDLE PortHandle,
			_In_ PPORT_MESSAGE PortMessage,
			_In_ ULONG Flags,
			_In_ ACCESS_MASK DesiredAccess,
			_In_ POBJECT_ATTRIBUTES ObjectAttributes
		);
#endif

	// Support functions

#if defined(_KERNEL_MODE) && NTDDI_VERSION >= NTDDI_WIN10_RS3
	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSYSAPI
		NTSTATUS
		NTAPI
		AlpcCreateSecurityContext(
			_In_ PVOID PortAddress,
			_In_ struct _ETHREAD* TargetThread,
			_Reserved_ ULONG Flags,
			_Inout_opt_ PALPC_SECURITY_ATTR SecurityAttribute
		);
#endif

	NTSYSAPI
		ULONG
		NTAPI
		AlpcGetHeaderSize(
			_In_ ULONG Flags
		);

	NTSYSAPI
		PVOID
		NTAPI
		AlpcGetMessageAttribute(
			_In_ PALPC_MESSAGE_ATTRIBUTES Buffer,
			_In_ ULONG AttributeFlag
		);

#define ALPC_ATTRFLG_ALLOCATEDATTR 0x20000000
#define ALPC_ATTRFLG_VALIDATTR 0x40000000
#define ALPC_ATTRFLG_KEEPRUNNINGATTR 0x60000000

	NTSYSAPI
		NTSTATUS
		NTAPI
		AlpcInitializeMessageAttribute(
			_In_ ULONG AttributeFlags,
			_Out_opt_ PALPC_MESSAGE_ATTRIBUTES Buffer,
			_In_ ULONG BufferSize,
			_Out_ PSIZE_T RequiredBufferSize // Changed from PULONG
		);

#ifndef _KERNEL_MODE
	NTSYSAPI
		ULONG
		NTAPI
		AlpcMaxAllowedMessageLength(
		);

	NTSYSAPI
		NTSTATUS
		NTAPI
		AlpcRegisterCompletionList(
			_In_ HANDLE PortHandle,
			_Out_ PALPC_COMPLETION_LIST_HEADER Buffer,
			_In_ ULONG Size,
			_In_ ULONG ConcurrencyCount,
			_In_ ULONG AttributeFlags
		);

	NTSYSAPI
		NTSTATUS
		NTAPI
		AlpcUnregisterCompletionList(
			_In_ HANDLE PortHandle
		);

#if (NTDDI_VERSION >= NTDDI_WIN7)
	NTSYSAPI
		NTSTATUS
		NTAPI
		AlpcRundownCompletionList(
			_In_ HANDLE PortHandle
		);
#endif

	NTSYSAPI
		NTSTATUS
		NTAPI
		AlpcAdjustCompletionListConcurrencyCount(
			_In_ HANDLE PortHandle,
			_In_ ULONG ConcurrencyCount
		);

	NTSYSAPI
		BOOLEAN
		NTAPI
		AlpcRegisterCompletionListWorkerThread(
			_Inout_ PVOID CompletionList
		);

	NTSYSAPI
		BOOLEAN
		NTAPI
		AlpcUnregisterCompletionListWorkerThread(
			_Inout_ PVOID CompletionList
		);

	NTSYSAPI
		VOID
		NTAPI
		AlpcGetCompletionListLastMessageInformation(
			_In_ PVOID CompletionList,
			_Out_ PULONG LastMessageId,
			_Out_ PULONG LastCallbackId
		);

	NTSYSAPI
		ULONG
		NTAPI
		AlpcGetOutstandingCompletionListMessageCount(
			_In_ PVOID CompletionList
		);

	NTSYSAPI
		PPORT_MESSAGE
		NTAPI
		AlpcGetMessageFromCompletionList(
			_In_ PVOID CompletionList,
			_Out_opt_ PALPC_MESSAGE_ATTRIBUTES* MessageAttributes
		);

	NTSYSAPI
		VOID
		NTAPI
		AlpcFreeCompletionListMessage(
			_Inout_ PVOID CompletionList,
			_In_ PPORT_MESSAGE Message
		);

	NTSYSAPI
		PALPC_MESSAGE_ATTRIBUTES
		NTAPI
		AlpcGetCompletionListMessageAttributes(
			_In_ PVOID CompletionList,
			_In_ PPORT_MESSAGE Message
		);
#endif // !_KERNEL_MODE

#endif // NTDDI_VERSION >= NTDDI_VISTA


#ifdef __cplusplus
}
#endif

typedef struct
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
} SYSTEM_MODULE, * PSYSTEM_MODULE;
typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG_PTR     ModuleCount;
	SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
}SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;