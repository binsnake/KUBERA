#pragma once
#include <cstdint>
#include <context/KUBERA.hpp>

namespace windows
{
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

	union _ULARGE_INTEGER {
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

	union _LARGE_INTEGER {
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

	inline uint64_t peb_address = 0;
	void setup_fake_peb ( kubera::KUBERA& ctx, uint64_t image_base );
}
