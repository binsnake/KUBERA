#pragma once

#include <cstdint>
#include <context/KUBERA.hpp>

namespace windows
{
	constexpr uint16_t code_segment = 0x33;
	constexpr uint16_t data_segment = 0x2B;
	constexpr uint16_t e_segment = 0x2B;
	constexpr uint16_t g_segment = 0x2B;
	constexpr uint16_t file_segment = 0x53;
	constexpr uint16_t segment_selector = 0x2B;
	constexpr x86::Flags rflags { .value = 0x0000000000000300 };
	constexpr x86::Mxcsr mxcsr { .value = 0x00001F80 };
	constexpr x86::FPUControlWord fpu_control_word { .value = 0x027F };
	constexpr x86::FPUStatusWord fpu_status_word = { .value = 0x0 };

	inline uint64_t peb_address = 0;
	void setup_fake_peb ( kubera::KUBERA& ctx, uint64_t image_base );

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
	typedef unsigned short USHORT;

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
	struct CLIENT_ID64 {
		ULONGLONG UniqueProcess;                                                //0x0
		ULONGLONG UniqueThread;                                                 //0x8
	};
	struct PEB64 {
		uint8_t  InheritedAddressSpace;
		uint8_t  ReadImageFileExecOptions;
		uint8_t  BeingDebugged;
		uint8_t  BitField;
		uint8_t  Padding0 [ 4 ];
		uint64_t Mutant;
		uint64_t ImageBaseAddress;
		uint64_t Ldr;
		uint64_t ProcessParameters;
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
};