#pragma once

#include <cstdint>
#include <context/KUBERA.hpp>

#define CONTEXT_AMD64   0x00100000L

#define CONTEXT_CONTROL         (CONTEXT_AMD64 | 0x00000001L)
#define CONTEXT_INTEGER         (CONTEXT_AMD64 | 0x00000002L)
#define CONTEXT_SEGMENTS        (CONTEXT_AMD64 | 0x00000004L)
#define CONTEXT_FLOATING_POINT  (CONTEXT_AMD64 | 0x00000008L)
#define CONTEXT_DEBUG_REGISTERS (CONTEXT_AMD64 | 0x00000010L)

#define CONTEXT_FULL            (CONTEXT_CONTROL | CONTEXT_INTEGER | \
                                 CONTEXT_FLOATING_POINT)

#define CONTEXT_ALL             (CONTEXT_CONTROL | CONTEXT_INTEGER | \
                                 CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | \
                                 CONTEXT_DEBUG_REGISTERS)

#define CONTEXT_XSTATE          (CONTEXT_AMD64 | 0x00000040L)
#define CONTEXT_KERNEL_CET      (CONTEXT_AMD64 | 0x00000080L)

namespace windows
{
	constexpr uint16_t code_segment = 0x33;
	constexpr uint16_t data_segment = 0x2B;
	constexpr uint16_t extra_segment = 0x2B;
	constexpr uint16_t g_segment = 0x2B;
	constexpr uint16_t file_segment = 0x53;
	constexpr uint16_t stack_segment = 0x2B;
	constexpr x86::Flags rflags { .value = 0x0000000000000300 };
	constexpr x86::Mxcsr mxcsr { .value = 0x00001F80 };
	constexpr x86::FPUControlWord fpu_control_word { .value = 0x027F };
	constexpr x86::FPUStatusWord fpu_status_word = { .value = 0x0 };

	inline uint64_t peb_address = 0;
	inline uint64_t teb_address = 0;
	void setup_fake_peb ( kubera::KUBERA& ctx, uint64_t image_base );
	void setup_fake_teb ( kubera::KUBERA& ctx );
	void setup_user_shared_data ( kubera::KUBERA& ctx );

	inline uint64_t ldr_initialize_thunk = 0ULL;
	inline uint64_t rtl_user_thread_start = 0ULL;
	inline uint64_t ki_user_apc_dispatcher = 0ULL;
	inline uint64_t ki_user_exception_dispatcher = 0ULL;
	inline void* ntdll = nullptr;
	inline void* win32u = nullptr;

	inline void* emu_module = nullptr;

#pragma pack(push,1)
	struct LIST_ENTRY64 {
		uint64_t Flink;
		uint64_t Blink;
	};

	struct STRING64 {
		uint16_t Length;
		uint16_t MaximumLength;
		uint64_t Buffer;
	};

	typedef unsigned long ULONG;
	typedef long LONG;
	typedef long long LONGLONG;
	typedef unsigned long long ULONGLONG;
	typedef unsigned char BYTE;
	typedef unsigned char UCHAR;
	typedef char CHAR;
	typedef wchar_t WCHAR;
	typedef unsigned short WORD;
	typedef unsigned int DWORD;
	typedef unsigned long long DWORD64;
	typedef unsigned short USHORT;

	typedef long NTSTATUS;
	typedef void* PVOID;
	typedef unsigned long long SIZE_T;
	typedef unsigned long long* PSIZE_T;
	typedef unsigned int ACCESS_MASK;
	typedef unsigned int* PACCESS_MASK;
	typedef bool BOOLEAN;
	typedef bool* PBOOLEAN;
	typedef unsigned long* PULONG;
	typedef long* PLONG;
	typedef enum _EVENT_TYPE {
		NotificationEvent,
		SynchronizationEvent
	} EVENT_TYPE;

	union ULARGE_INTEGER {
		struct {
			ULONG LowPart;
			ULONG HighPart;
		};
		struct {
			ULONG LowPart;
			ULONG HighPart;
		} u;
		ULONGLONG QuadPart;
	};

	union LARGE_INTEGER {
		struct {
			ULONG LowPart;
			LONG HighPart;
		};
		struct {
			ULONG LowPart;
			LONG HighPart;
		} u;
		LONGLONG QuadPart;
	};

	typedef LARGE_INTEGER* PLARGE_INTEGER;

	struct CLIENT_ID64 {
		ULONGLONG UniqueProcess;                                                //0x0
		ULONGLONG UniqueThread;                                                 //0x8
	};

	typedef struct _PROCESSOR_NUMBER {
		WORD   Group;
		BYTE  Number;
		BYTE  Reserved;
	} PROCESSOR_NUMBER, * PPROCESSOR_NUMBER;

	struct _GUID {
		ULONG Data1;                                                            //0x0
		USHORT Data2;                                                           //0x4
		USHORT Data3;                                                           //0x6
		UCHAR Data4 [ 8 ];                                                         //0x8
	};

	struct _GROUP_AFFINITY64 {
		ULONGLONG Mask;                                                         //0x0
		USHORT Group;                                                           //0x8
		USHORT Reserved [ 3 ];                                                     //0xa
	};

	typedef struct _UNICODE_STRING {
		USHORT Length;                                                          //0x0
		USHORT MaximumLength;                                                   //0x2
		char16_t* Buffer;                                                          //0x8
	} *PUNICODE_STRING;

	typedef struct _OBJECT_ATTRIBUTES {
		ULONG Length;                                                           //0x0
		void* RootDirectory;                                                    //0x8
		_UNICODE_STRING* ObjectName;                                     //0x10
		ULONG Attributes;                                                       //0x18
		void* SecurityDescriptor;                                               //0x20
		void* SecurityQualityOfService;                                         //0x28
	} *POBJECT_ATTRIBUTES;

	struct _CURDIR {
		_UNICODE_STRING DosPath;                                         //0x0
		void* Handle;                                                           //0x10
	};
	struct _STRING {
		USHORT Length;                                                          //0x0
		USHORT MaximumLength;                                                   //0x2
		CHAR* Buffer;                                                           //0x8
	};
	struct _RTL_DRIVE_LETTER_CURDIR {
		USHORT Flags;                                                           //0x0
		USHORT Length;                                                          //0x2
		ULONG TimeStamp;                                                        //0x4
		_STRING DosPath;                                                 //0x8
	};

	typedef struct _LIST_ENTRY {
		ULONGLONG Flink;                                                        //0x0
		ULONGLONG Blink;                                                        //0x8
	} *PLIST_ENTRY;

	struct _PEB_LDR_DATA {
		ULONG Length;                                                           //0x0
		UCHAR Initialized;                                                      //0x4
		void* SsHandle;                                                         //0x8
		_LIST_ENTRY InLoadOrderModuleList;                               //0x10
		_LIST_ENTRY InMemoryOrderModuleList;                             //0x20
		_LIST_ENTRY InInitializationOrderModuleList;                     //0x30
		void* EntryInProgress;                                                  //0x40
		UCHAR ShutdownInProgress;                                               //0x48
		void* ShutdownThreadId;                                                 //0x50
	};

	struct _RTL_USER_PROCESS_PARAMETERS {
		ULONG MaximumLength;                                                    //0x0
		ULONG Length;                                                           //0x4
		ULONG Flags;                                                            //0x8
		ULONG DebugFlags;                                                       //0xc
		void* ConsoleHandle;                                                    //0x10
		ULONG ConsoleFlags;                                                     //0x18
		void* StandardInput;                                                    //0x20
		void* StandardOutput;                                                   //0x28
		void* StandardError;                                                    //0x30
		_CURDIR CurrentDirectory;                                        //0x38
		_UNICODE_STRING DllPath;                                         //0x50
		_UNICODE_STRING ImagePathName;                                   //0x60
		_UNICODE_STRING CommandLine;                                     //0x70
		void* Environment;                                                      //0x80
		ULONG StartingX;                                                        //0x88
		ULONG StartingY;                                                        //0x8c
		ULONG CountX;                                                           //0x90
		ULONG CountY;                                                           //0x94
		ULONG CountCharsX;                                                      //0x98
		ULONG CountCharsY;                                                      //0x9c
		ULONG FillAttribute;                                                    //0xa0
		ULONG WindowFlags;                                                      //0xa4
		ULONG ShowWindowFlags;                                                  //0xa8
		_UNICODE_STRING WindowTitle;                                     //0xb0
		_UNICODE_STRING DesktopInfo;                                     //0xc0
		_UNICODE_STRING ShellInfo;                                       //0xd0
		_UNICODE_STRING RuntimeData;                                     //0xe0
		_RTL_DRIVE_LETTER_CURDIR CurrentDirectores [ 32 ];                  //0xf0
		ULONGLONG EnvironmentSize;                                              //0x3f0
		ULONGLONG EnvironmentVersion;                                           //0x3f8
		void* PackageDependencyData;                                            //0x400
		ULONG ProcessGroupId;                                                   //0x408
		ULONG LoaderThreads;                                                    //0x40c
		_UNICODE_STRING RedirectionDllName;                              //0x410
		_UNICODE_STRING HeapPartitionName;                               //0x420
		ULONGLONG* DefaultThreadpoolCpuSetMasks;                                //0x430
		ULONG DefaultThreadpoolCpuSetMaskCount;                                 //0x438
		ULONG DefaultThreadpoolThreadMaximum;                                   //0x43c
		ULONG HeapMemoryTypeMask;                                               //0x440
	};

	struct PEB64 {
		uint8_t  InheritedAddressSpace;
		uint8_t  ReadImageFileExecOptions;
		uint8_t  BeingDebugged;
		uint8_t  BitField;
		uint8_t  Padding0 [ 4 ];
		uint64_t Mutant;
		uint64_t ImageBaseAddress;
		_PEB_LDR_DATA* Ldr;
		_RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
		uint64_t SubSystemData;
		uint64_t ProcessHeap;
		uint64_t FastPebLock;
		uint64_t AtlThunkSListPtr;
		uint64_t IFEOKey;
		uint32_t CrossProcessFlags;
		uint8_t  Padding1 [ 4 ];
		uint64_t KernelCallbackTable;
		uint32_t SystemReserved;
		uint32_t AtlThunkSListPtr32;
		uint64_t ApiSetMap;
		uint32_t TlsExpansionCounter;
		uint8_t  Padding2 [ 4 ];
		uint64_t TlsBitmap;
		uint32_t TlsBitmapBits [ 2 ];
		uint64_t ReadOnlySharedMemoryBase;
		uint64_t SharedData;
		uint64_t ReadOnlyStaticServerData;
		uint64_t AnsiCodePageData;
		uint64_t OemCodePageData;
		uint64_t UnicodeCaseTableData;
		uint32_t NumberOfProcessors;
		uint32_t NtGlobalFlag;
		LARGE_INTEGER CriticalSectionTimeout;
		uint64_t HeapSegmentReserve;
		uint64_t HeapSegmentCommit;
		uint64_t HeapDeCommitTotalFreeThreshold;
		uint64_t HeapDeCommitFreeBlockThreshold;
		uint32_t NumberOfHeaps;
		uint32_t MaximumNumberOfHeaps;
		uint64_t ProcessHeaps;
		uint64_t GdiSharedHandleTable;
		uint64_t ProcessStarterHelper;
		uint32_t GdiDCAttributeList;
		uint8_t  Padding3 [ 4 ];
		uint64_t LoaderLock;
		uint32_t OSMajorVersion;
		uint32_t OSMinorVersion;
		uint16_t OSBuildNumber;
		uint16_t OSCSDVersion;
		uint32_t OSPlatformId;
		uint32_t ImageSubsystem;
		uint32_t ImageSubsystemMajorVersion;
		uint32_t ImageSubsystemMinorVersion;
		uint8_t  Padding4 [ 4 ];
		uint64_t ActiveProcessAffinityMask;
		uint32_t GdiHandleBuffer [ 60 ];
		uint64_t PostProcessInitRoutine;
		uint64_t TlsExpansionBitmap;
		uint32_t TlsExpansionBitmapBits [ 32 ];
		uint32_t SessionId;
		uint8_t  Padding5 [ 4 ];
		ULARGE_INTEGER AppCompatFlags;
		ULARGE_INTEGER AppCompatFlagsUser;
		uint64_t pShimData;
		uint64_t AppCompatInfo;
		STRING64 CSDVersion;
		uint64_t ActivationContextData;
		uint64_t ProcessAssemblyStorageMap;
		uint64_t SystemDefaultActivationContextData;
		uint64_t SystemAssemblyStorageMap;
		uint64_t MinimumStackCommit;
		uint64_t SparePointers [ 2 ];
		uint64_t PatchLoaderData;
		uint64_t ChpeV2ProcessInfo;
		uint32_t AppModelFeatureState;
		uint32_t SpareUlongs [ 2 ];
		uint16_t ActiveCodePage;
		uint16_t OemCodePage;
		uint16_t UseCaseMapping;
		uint16_t UnusedNlsField;
		uint64_t WerRegistrationData;
		uint64_t WerShipAssertPtr;
		uint64_t EcCodeBitMap;
		uint64_t pImageHeaderHash;
		uint32_t TracingFlags;
		uint8_t  Padding6 [ 4 ];
		uint64_t CsrServerReadOnlySharedMemoryBase;
		uint64_t TppWorkerpListLock;
		LIST_ENTRY64 TppWorkerpList;
		uint64_t WaitOnAddressHashTable [ 128 ];
		uint64_t TelemetryCoverageHeader;
		uint32_t CloudFileFlags;
		uint32_t CloudFileDiagFlags;
		char     PlaceholderCompatibilityMode;
		char     PlaceholderCompatibilityModeReserved [ 7 ];
		uint64_t LeapSecondData;
		uint32_t LeapSecondFlags;
		uint32_t NtGlobalFlag2;
		uint64_t ExtendedFeatureDisableMask;
	};
#pragma pack(pop)

	struct _NT_TIB64 {
		ULONGLONG ExceptionList;                                                //0x0
		ULONGLONG StackBase;                                                    //0x8
		ULONGLONG StackLimit;                                                   //0x10
		ULONGLONG SubSystemTib;                                                 //0x18
		union {
			ULONGLONG FiberData;                                                //0x20
			ULONG Version;                                                      //0x20
		};
		ULONGLONG ArbitraryUserPointer;                                         //0x28
		ULONGLONG Self;                                                         //0x30
	};

	struct _ACTIVATION_CONTEXT_STACK64 {
		ULONGLONG ActiveFrame;                                                  //0x0
		struct LIST_ENTRY64 FrameListCache;                                     //0x8
		ULONG Flags;                                                            //0x18
		ULONG NextCookieSequenceNumber;                                         //0x1c
		ULONG StackId;                                                          //0x20
	};

	struct _GDI_TEB_BATCH64 {
		ULONG Offset : 30;                                                        //0x0
		ULONG InProcessing : 1;                                                   //0x0
		ULONG HasRenderingCommand : 1;                                            //0x0
		ULONGLONG HDC;                                                          //0x8
		ULONG Buffer [ 310 ];                                                      //0x10
	};

	struct TEB64 {
		_NT_TIB64 NtTib;                                                 //0x0
		ULONGLONG EnvironmentPointer;                                           //0x38
		CLIENT_ID64 ClientId;                                           //0x40
		ULONGLONG ActiveRpcHandle;                                              //0x50
		ULONGLONG ThreadLocalStoragePointer;                                    //0x58
		ULONGLONG ProcessEnvironmentBlock;                                      //0x60
		ULONG LastErrorValue;                                                   //0x68
		ULONG CountOfOwnedCriticalSections;                                     //0x6c
		ULONGLONG CsrClientThread;                                              //0x70
		ULONGLONG Win32ThreadInfo;                                              //0x78
		ULONG User32Reserved [ 26 ];                                               //0x80
		ULONG UserReserved [ 5 ];                                                  //0xe8
		ULONGLONG WOW32Reserved;                                                //0x100
		ULONG CurrentLocale;                                                    //0x108
		ULONG FpSoftwareStatusRegister;                                         //0x10c
		ULONGLONG ReservedForDebuggerInstrumentation [ 16 ];                       //0x110
		ULONGLONG SystemReserved1 [ 25 ];                                          //0x190
		ULONGLONG HeapFlsData;                                                  //0x258
		ULONGLONG RngState [ 4 ];                                                  //0x260
		CHAR PlaceholderCompatibilityMode;                                      //0x280
		UCHAR PlaceholderHydrationAlwaysExplicit;                               //0x281
		CHAR PlaceholderReserved [ 10 ];                                           //0x282
		ULONG ProxiedProcessId;                                                 //0x28c
		_ACTIVATION_CONTEXT_STACK64 _ActivationStack;                    //0x290
		UCHAR WorkingOnBehalfTicket [ 8 ];                                         //0x2b8
		LONG ExceptionCode;                                                     //0x2c0
		UCHAR Padding0 [ 4 ];                                                      //0x2c4
		ULONGLONG ActivationContextStackPointer;                                //0x2c8
		ULONGLONG InstrumentationCallbackSp;                                    //0x2d0
		ULONGLONG InstrumentationCallbackPreviousPc;                            //0x2d8
		ULONGLONG InstrumentationCallbackPreviousSp;                            //0x2e0
		ULONG TxFsContext;                                                      //0x2e8
		UCHAR InstrumentationCallbackDisabled;                                  //0x2ec
		UCHAR UnalignedLoadStoreExceptions;                                     //0x2ed
		UCHAR Padding1 [ 2 ];                                                      //0x2ee
		_GDI_TEB_BATCH64 GdiTebBatch;                                    //0x2f0
		CLIENT_ID64 RealClientId;                                       //0x7d8
		ULONGLONG GdiCachedProcessHandle;                                       //0x7e8
		ULONG GdiClientPID;                                                     //0x7f0
		ULONG GdiClientTID;                                                     //0x7f4
		ULONGLONG GdiThreadLocalInfo;                                           //0x7f8
		ULONGLONG Win32ClientInfo [ 62 ];                                          //0x800
		ULONGLONG glDispatchTable [ 233 ];                                         //0x9f0
		ULONGLONG glReserved1 [ 29 ];                                              //0x1138
		ULONGLONG glReserved2;                                                  //0x1220
		ULONGLONG glSectionInfo;                                                //0x1228
		ULONGLONG glSection;                                                    //0x1230
		ULONGLONG glTable;                                                      //0x1238
		ULONGLONG glCurrentRC;                                                  //0x1240
		ULONGLONG glContext;                                                    //0x1248
		ULONG LastStatusValue;                                                  //0x1250
		UCHAR Padding2 [ 4 ];                                                      //0x1254
		STRING64 StaticUnicodeString;                                   //0x1258
		WCHAR StaticUnicodeBuffer [ 261 ];                                         //0x1268
		UCHAR Padding3 [ 6 ];                                                      //0x1472
		ULONGLONG DeallocationStack;                                            //0x1478
		ULONGLONG TlsSlots [ 64 ];                                                 //0x1480
		LIST_ENTRY64 TlsLinks;                                           //0x1680
		ULONGLONG Vdm;                                                          //0x1690
		ULONGLONG ReservedForNtRpc;                                             //0x1698
		ULONGLONG DbgSsReserved [ 2 ];                                             //0x16a0
		ULONG HardErrorMode;                                                    //0x16b0
		UCHAR Padding4 [ 4 ];                                                      //0x16b4
		ULONGLONG Instrumentation [ 11 ];                                          //0x16b8
		_GUID ActivityId;                                                //0x1710
		ULONGLONG SubProcessTag;                                                //0x1720
		ULONGLONG PerflibData;                                                  //0x1728
		ULONGLONG EtwTraceData;                                                 //0x1730
		ULONGLONG WinSockData;                                                  //0x1738
		ULONG GdiBatchCount;                                                    //0x1740
		union {
			struct _PROCESSOR_NUMBER CurrentIdealProcessor;                     //0x1744
			ULONG IdealProcessorValue;                                          //0x1744
			struct {
				UCHAR ReservedPad0;                                             //0x1744
				UCHAR ReservedPad1;                                             //0x1745
				UCHAR ReservedPad2;                                             //0x1746
				UCHAR IdealProcessor;                                           //0x1747
			};
		};
		ULONG GuaranteedStackBytes;                                             //0x1748
		UCHAR Padding5 [ 4 ];                                                      //0x174c
		ULONGLONG ReservedForPerf;                                              //0x1750
		ULONGLONG ReservedForOle;                                               //0x1758
		ULONG WaitingOnLoaderLock;                                              //0x1760
		UCHAR Padding6 [ 4 ];                                                      //0x1764
		ULONGLONG SavedPriorityState;                                           //0x1768
		ULONGLONG ReservedForCodeCoverage;                                      //0x1770
		ULONGLONG ThreadPoolData;                                               //0x1778
		ULONGLONG TlsExpansionSlots;                                            //0x1780
		ULONGLONG ChpeV2CpuAreaInfo;                                            //0x1788
		ULONGLONG Unused;                                                       //0x1790
		ULONG MuiGeneration;                                                    //0x1798
		ULONG IsImpersonating;                                                  //0x179c
		ULONGLONG NlsCache;                                                     //0x17a0
		ULONGLONG pShimData;                                                    //0x17a8
		ULONG HeapData;                                                         //0x17b0
		UCHAR Padding7 [ 4 ];                                                      //0x17b4
		ULONGLONG CurrentTransactionHandle;                                     //0x17b8
		ULONGLONG ActiveFrame;                                                  //0x17c0
		ULONGLONG FlsData;                                                      //0x17c8
		ULONGLONG PreferredLanguages;                                           //0x17d0
		ULONGLONG UserPrefLanguages;                                            //0x17d8
		ULONGLONG MergedPrefLanguages;                                          //0x17e0
		ULONG MuiImpersonation;                                                 //0x17e8
		union {
			volatile USHORT CrossTebFlags;                                      //0x17ec
			USHORT SpareCrossTebBits : 16;                                        //0x17ec
		};
		union {
			USHORT SameTebFlags;                                                //0x17ee
			struct {
				USHORT SafeThunkCall : 1;                                         //0x17ee
				USHORT InDebugPrint : 1;                                          //0x17ee
				USHORT HasFiberData : 1;                                          //0x17ee
				USHORT SkipThreadAttach : 1;                                      //0x17ee
				USHORT WerInShipAssertCode : 1;                                   //0x17ee
				USHORT RanProcessInit : 1;                                        //0x17ee
				USHORT ClonedThread : 1;                                          //0x17ee
				USHORT SuppressDebugMsg : 1;                                      //0x17ee
				USHORT DisableUserStackWalk : 1;                                  //0x17ee
				USHORT RtlExceptionAttached : 1;                                  //0x17ee
				USHORT InitialThread : 1;                                         //0x17ee
				USHORT SessionAware : 1;                                          //0x17ee
				USHORT LoadOwner : 1;                                             //0x17ee
				USHORT LoaderWorker : 1;                                          //0x17ee
				USHORT SkipLoaderInit : 1;                                        //0x17ee
				USHORT SkipFileAPIBrokering : 1;                                  //0x17ee
			};
		};
		ULONGLONG TxnScopeEnterCallback;                                        //0x17f0
		ULONGLONG TxnScopeExitCallback;                                         //0x17f8
		ULONGLONG TxnScopeContext;                                              //0x1800
		ULONG LockCount;                                                        //0x1808
		LONG WowTebOffset;                                                      //0x180c
		ULONGLONG ResourceRetValue;                                             //0x1810
		ULONGLONG ReservedForWdf;                                               //0x1818
		ULONGLONG ReservedForCrt;                                               //0x1820
		struct _GUID EffectiveContainerId;                                      //0x1828
		ULONGLONG LastSleepCounter;                                             //0x1838
		ULONG SpinCallCount;                                                    //0x1840
		UCHAR Padding8 [ 4 ];                                                      //0x1844
		ULONGLONG ExtendedFeatureDisableMask;                                   //0x1848
		ULONGLONG SchedulerSharedDataSlot;                                      //0x1850
		ULONGLONG HeapWalkContext;                                              //0x1858
		struct _GROUP_AFFINITY64 PrimaryGroupAffinity;                          //0x1860
		ULONG Rcu [ 2 ];                                                           //0x1870
	};

	struct _KSYSTEM_TIME {
		ULONG LowPart;                                                          //0x0
		LONG High1Time;                                                         //0x4
		LONG High2Time;                                                         //0x8
	};

	struct _XSTATE_FEATURE {
		ULONG Offset;                                                           //0x0
		ULONG Size;                                                             //0x4
	};

	struct _XSTATE_CONFIGURATION {
		ULONGLONG EnabledFeatures;                                              //0x0
		ULONGLONG EnabledVolatileFeatures;                                      //0x8
		ULONG Size;                                                             //0x10
		union {
			ULONG ControlFlags;                                                 //0x14
			struct {
				ULONG OptimizedSave : 1;                                          //0x14
				ULONG CompactionEnabled : 1;                                      //0x14
				ULONG ExtendedFeatureDisable : 1;                                 //0x14
			};
		};
		struct _XSTATE_FEATURE Features [ 64 ];                                    //0x18
		ULONGLONG EnabledSupervisorFeatures;                                    //0x218
		ULONGLONG AlignedFeatures;                                              //0x220
		ULONG AllFeatureSize;                                                   //0x228
		ULONG AllFeatures [ 64 ];                                                  //0x22c
		ULONGLONG EnabledUserVisibleSupervisorFeatures;                         //0x330
		ULONGLONG ExtendedFeatureDisableFeatures;                               //0x338
		ULONG AllNonLargeFeatureSize;                                           //0x340
		USHORT MaxSveVectorLength;                                              //0x344
		USHORT Spare1;                                                          //0x346
	};

	enum _NT_PRODUCT_TYPE {
		NtProductWinNt = 1,
		NtProductLanManNt = 2,
		NtProductServer = 3
	};

	enum _ALTERNATIVE_ARCHITECTURE_TYPE {
		StandardDesign = 0,
		NEC98x86 = 1,
		EndAlternatives = 2
	};

	struct _KUSER_SHARED_DATA {
		ULONG TickCountLowDeprecated;                                           //0x0
		ULONG TickCountMultiplier;                                              //0x4
		volatile _KSYSTEM_TIME InterruptTime;                            //0x8
		volatile _KSYSTEM_TIME SystemTime;                               //0x14
		volatile _KSYSTEM_TIME TimeZoneBias;                             //0x20
		USHORT ImageNumberLow;                                                  //0x2c
		USHORT ImageNumberHigh;                                                 //0x2e
		char16_t NtSystemRoot [ 260 ];                                                //0x30
		ULONG MaxStackTraceDepth;                                               //0x238
		ULONG CryptoExponent;                                                   //0x23c
		ULONG TimeZoneId;                                                       //0x240
		ULONG LargePageMinimum;                                                 //0x244
		ULONG AitSamplingValue;                                                 //0x248
		ULONG AppCompatFlag;                                                    //0x24c
		ULONGLONG RNGSeedVersion;                                               //0x250
		ULONG GlobalValidationRunlevel;                                         //0x258
		volatile LONG TimeZoneBiasStamp;                                        //0x25c
		ULONG NtBuildNumber;                                                    //0x260
		_NT_PRODUCT_TYPE NtProductType;                                    //0x264
		UCHAR ProductTypeIsValid;                                               //0x268
		UCHAR Reserved0 [ 1 ];                                                     //0x269
		USHORT NativeProcessorArchitecture;                                     //0x26a
		ULONG NtMajorVersion;                                                   //0x26c
		ULONG NtMinorVersion;                                                   //0x270
		UCHAR ProcessorFeatures [ 64 ];                                            //0x274
		ULONG Reserved1;                                                        //0x2b4
		ULONG Reserved3;                                                        //0x2b8
		volatile ULONG TimeSlip;                                                //0x2bc
		_ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;            //0x2c0
		ULONG BootId;                                                           //0x2c4
		LARGE_INTEGER SystemExpirationDate;                              //0x2c8
		ULONG SuiteMask;                                                        //0x2d0
		UCHAR KdDebuggerEnabled;                                                //0x2d4
		union {
			UCHAR MitigationPolicies;                                           //0x2d5
			struct {
				UCHAR NXSupportPolicy : 2;                                        //0x2d5
				UCHAR SEHValidationPolicy : 2;                                    //0x2d5
				UCHAR CurDirDevicesSkippedForDlls : 2;                            //0x2d5
				UCHAR Reserved : 2;                                               //0x2d5
			};
		};
		USHORT CyclesPerYield;                                                  //0x2d6
		volatile ULONG ActiveConsoleId;                                         //0x2d8
		volatile ULONG DismountCount;                                           //0x2dc
		ULONG ComPlusPackage;                                                   //0x2e0
		ULONG LastSystemRITEventTickCount;                                      //0x2e4
		ULONG NumberOfPhysicalPages;                                            //0x2e8
		UCHAR SafeBootMode;                                                     //0x2ec
		UCHAR VirtualizationFlags;                                              //0x2ed
		UCHAR Reserved12 [ 2 ];                                                    //0x2ee
		union {
			ULONG SharedDataFlags;                                              //0x2f0
			struct {
				ULONG DbgErrorPortPresent : 1;                                    //0x2f0
				ULONG DbgElevationEnabled : 1;                                    //0x2f0
				ULONG DbgVirtEnabled : 1;                                         //0x2f0
				ULONG DbgInstallerDetectEnabled : 1;                              //0x2f0
				ULONG DbgLkgEnabled : 1;                                          //0x2f0
				ULONG DbgDynProcessorEnabled : 1;                                 //0x2f0
				ULONG DbgConsoleBrokerEnabled : 1;                                //0x2f0
				ULONG DbgSecureBootEnabled : 1;                                   //0x2f0
				ULONG DbgMultiSessionSku : 1;                                     //0x2f0
				ULONG DbgMultiUsersInSessionSku : 1;                              //0x2f0
				ULONG DbgStateSeparationEnabled : 1;                              //0x2f0
				ULONG SpareBits : 21;                                             //0x2f0
			};
		};
		ULONG DataFlagsPad [ 1 ];                                                  //0x2f4
		ULONGLONG TestRetInstruction;                                           //0x2f8
		LONGLONG QpcFrequency;                                                  //0x300
		ULONG SystemCall;                                                       //0x308
		ULONG Reserved2;                                                        //0x30c
		ULONGLONG FullNumberOfPhysicalPages;                                    //0x310
		ULONGLONG SystemCallPad [ 1 ];                                             //0x318
		union {
			volatile _KSYSTEM_TIME TickCount;                            //0x320
			volatile ULONGLONG TickCountQuad;                                   //0x320
			ULONG ReservedTickCountOverlay [ 3 ];                                  //0x320
		};
		ULONG TickCountPad [ 1 ];                                                  //0x32c
		ULONG Cookie;                                                           //0x330
		ULONG CookiePad [ 1 ];                                                     //0x334
		LONGLONG ConsoleSessionForegroundProcessId;                             //0x338
		ULONGLONG TimeUpdateLock;                                               //0x340
		ULONGLONG BaselineSystemTimeQpc;                                        //0x348
		ULONGLONG BaselineInterruptTimeQpc;                                     //0x350
		ULONGLONG QpcSystemTimeIncrement;                                       //0x358
		ULONGLONG QpcInterruptTimeIncrement;                                    //0x360
		UCHAR QpcSystemTimeIncrementShift;                                      //0x368
		UCHAR QpcInterruptTimeIncrementShift;                                   //0x369
		USHORT UnparkedProcessorCount;                                          //0x36a
		ULONG EnclaveFeatureMask [ 4 ];                                            //0x36c
		ULONG TelemetryCoverageRound;                                           //0x37c
		USHORT UserModeGlobalLogger [ 16 ];                                        //0x380
		ULONG ImageFileExecutionOptions;                                        //0x3a0
		ULONG LangGenerationCount;                                              //0x3a4
		ULONGLONG Reserved4;                                                    //0x3a8
		volatile ULONGLONG InterruptTimeBias;                                   //0x3b0
		volatile ULONGLONG QpcBias;                                             //0x3b8
		ULONG ActiveProcessorCount;                                             //0x3c0
		volatile UCHAR ActiveGroupCount;                                        //0x3c4
		UCHAR Reserved9;                                                        //0x3c5
		union {
			USHORT QpcData;                                                     //0x3c6
			struct {
				volatile UCHAR QpcBypassEnabled;                                //0x3c6
				UCHAR QpcReserved;                                              //0x3c7
			};
		};
		LARGE_INTEGER TimeZoneBiasEffectiveStart;                        //0x3c8
		LARGE_INTEGER TimeZoneBiasEffectiveEnd;                          //0x3d0
		_XSTATE_CONFIGURATION XState;                                    //0x3d8
		_KSYSTEM_TIME FeatureConfigurationChangeStamp;                   //0x720
		ULONG Spare;                                                            //0x72c
		ULONGLONG UserPointerAuthMask;                                          //0x730
		ULONG Reserved10 [ 210 ];                                                  //0x738
	};

#pragma pack(push)
#pragma pack(1)
	struct handle_value {
		uint64_t id : 32;
		uint64_t type : 16;
		uint64_t padding : 14;
		uint64_t is_system : 1;
		uint64_t is_pseudo : 1;
	};
#pragma pack(pop)

	union HANDLE {
		handle_value value;
		uint64_t bits;
		std::uint64_t h;
	};

	typedef struct __declspec ( align(16) ) _M128A {
		ULONGLONG Low;
		LONGLONG High;
	} M128A, * PM128A;

	struct _XMM_SAVE_AREA32 {
		USHORT ControlWord;                                                     //0x0
		USHORT StatusWord;                                                      //0x2
		UCHAR TagWord;                                                          //0x4
		UCHAR Reserved1;                                                        //0x5
		USHORT ErrorOpcode;                                                     //0x6
		ULONG ErrorOffset;                                                      //0x8
		USHORT ErrorSelector;                                                   //0xc
		USHORT Reserved2;                                                       //0xe
		ULONG DataOffset;                                                       //0x10
		USHORT DataSelector;                                                    //0x14
		USHORT Reserved3;                                                       //0x16
		ULONG MxCsr;                                                            //0x18
		ULONG MxCsr_Mask;                                                       //0x1c
		struct _M128A FloatRegisters [ 8 ];                                        //0x20
		struct _M128A XmmRegisters [ 16 ];                                         //0xa0
		UCHAR Reserved4 [ 96 ];                                                    //0x1a0
	};

	typedef struct __declspec ( align( 16 ) ) __pragma( warning ( push ) ) __pragma( warning ( disable:4845 ) ) __declspec( no_init_all ) __pragma( warning ( pop ) ) _CONTEXT {

		//
		// Register parameter home addresses.
		//
		// N.B. These fields are for convience - they could be used to extend the
		//      context record in the future.
		//

		DWORD64 P1Home;
		DWORD64 P2Home;
		DWORD64 P3Home;
		DWORD64 P4Home;
		DWORD64 P5Home;
		DWORD64 P6Home;

		//
		// Control flags.
		//

		DWORD ContextFlags;
		DWORD MxCsr;

		//
		// Segment Registers and processor flags.
		//

		WORD   SegCs;
		WORD   SegDs;
		WORD   SegEs;
		WORD   SegFs;
		WORD   SegGs;
		WORD   SegSs;
		DWORD EFlags;

		//
		// Debug registers
		//

		DWORD64 Dr0;
		DWORD64 Dr1;
		DWORD64 Dr2;
		DWORD64 Dr3;
		DWORD64 Dr6;
		DWORD64 Dr7;

		//
		// Integer registers.
		//

		DWORD64 Rax;
		DWORD64 Rcx;
		DWORD64 Rdx;
		DWORD64 Rbx;
		DWORD64 Rsp;
		DWORD64 Rbp;
		DWORD64 Rsi;
		DWORD64 Rdi;
		DWORD64 R8;
		DWORD64 R9;
		DWORD64 R10;
		DWORD64 R11;
		DWORD64 R12;
		DWORD64 R13;
		DWORD64 R14;
		DWORD64 R15;

		//
		// Program counter.
		//

		DWORD64 Rip;

		//
		// Floating point state.
		//

		union {
			_XMM_SAVE_AREA32 FltSave;
			struct {
				M128A Header [ 2 ];
				M128A Legacy [ 8 ];
				M128A Xmm0;
				M128A Xmm1;
				M128A Xmm2;
				M128A Xmm3;
				M128A Xmm4;
				M128A Xmm5;
				M128A Xmm6;
				M128A Xmm7;
				M128A Xmm8;
				M128A Xmm9;
				M128A Xmm10;
				M128A Xmm11;
				M128A Xmm12;
				M128A Xmm13;
				M128A Xmm14;
				M128A Xmm15;
			} DUMMYSTRUCTNAME;
		} DUMMYUNIONNAME;

		//
		// Vector registers.
		//

		M128A VectorRegister [ 26 ];
		DWORD64 VectorControl;

		//
		// Special debug control registers.
		//

		DWORD64 DebugControl;
		DWORD64 LastBranchToRip;
		DWORD64 LastBranchFromRip;
		DWORD64 LastExceptionToRip;
		DWORD64 LastExceptionFromRip;
	} CONTEXT, *PCONTEXT;

	typedef struct _PROCESS_BASIC_INFORMATION {
		long ExitStatus;                    // The exit status of the process. (GetExitCodeProcess)
		PEB64* PebBaseAddress;                    // A pointer to the process environment block (PEB) of the process.
		uint64_t AffinityMask;                 // The affinity mask of the process. (GetProcessAffinityMask) (deprecated)
		LONG BasePriority;                 // The base priority of the process. (GetPriorityClass)
		HANDLE UniqueProcessId;                 // The unique identifier of the process. (GetProcessId)
		HANDLE InheritedFromUniqueProcessId;    // The unique identifier of the parent process.
	} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

	typedef struct _SYSTEM_BASIC_INFORMATION {
		ULONG Reserved;
		ULONG TimerResolution;
		ULONG PageSize;
		ULONG NumberOfPhysicalPages;
		ULONG LowestPhysicalPageNumber;
		ULONG HighestPhysicalPageNumber;
		ULONG AllocationGranularity;
		ULONGLONG MinimumUserModeAddress;
		ULONGLONG MaximumUserModeAddress;
		ULONGLONG ActiveProcessorsAffinityMask;
		char NumberOfProcessors;
	} SYSTEM_BASIC_INFORMATION, * PSYSTEM_BASIC_INFORMATION;


	typedef uint64_t* PHANDLE;
};

inline bool operator==( const windows::HANDLE& lhs, const windows::HANDLE& rhs ) {
	return lhs.bits == rhs.bits;
}

inline bool operator!=( const windows::HANDLE& lhs, const windows::HANDLE& rhs ) {
	return lhs.bits != rhs.bits;
}