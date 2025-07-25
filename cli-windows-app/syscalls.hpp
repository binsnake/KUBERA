#pragma once

#include <context/KUBERA.hpp>
#include <map>
#include <string>
#include "module_manager.hpp"

namespace syscall_handlers
{
	inline std::map <uint32_t, void ( * )( uint32_t, kubera::KUBERA& ctx )> handler_map;
	inline std::map <uint32_t, std::string> handler_name_map;
	inline std::map<std::string, uint32_t> syscall_map;
	void dispatcher ( const iced::Instruction& instr, kubera::KUBERA& ctx );
	void dispatcher_verbose ( const iced::Instruction& instr, kubera::KUBERA& ctx );

	void build_syscall_map ( kubera::KUBERA& ctx, ModuleManager& mm );

	template <bool verbose>
	void init ( );
};

using PROCESSINFOCLASS = enum _PROCESSINFOCLASS {
  ProcessBasicInformation,          // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
  ProcessQuotaLimits,               // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
  ProcessIoCounters,                // q: IO_COUNTERS
  ProcessVmCounters,                // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
  ProcessTimes,                     // q: KERNEL_USER_TIMES
  ProcessBasePriority,              // s: KPRIORITY
  ProcessRaisePriority,             // s: ULONG
  ProcessDebugPort,                 // q: HANDLE
  ProcessExceptionPort,             // s: PROCESS_EXCEPTION_PORT (requires SeTcbPrivilege)
  ProcessAccessToken,               // s: PROCESS_ACCESS_TOKEN
  ProcessLdtInformation,            // qs: PROCESS_LDT_INFORMATION // 10
  ProcessLdtSize,                   // s: PROCESS_LDT_SIZE
  ProcessDefaultHardErrorMode,      // qs: ULONG
  ProcessIoPortHandlers,            // (kernel-mode only) // s: PROCESS_IO_PORT_HANDLER_INFORMATION
  ProcessPooledUsageAndLimits,      // q: POOLED_USAGE_AND_LIMITS
  ProcessWorkingSetWatch,           // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
  ProcessUserModeIOPL,              // qs: ULONG (requires SeTcbPrivilege)
  ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
  ProcessPriorityClass,             // qs: PROCESS_PRIORITY_CLASS
  ProcessWx86Information,           // qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
  ProcessHandleCount,               // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
  ProcessAffinityMask,              // (q >WIN7)s: KAFFINITY, qs: GROUP_AFFINITY
  ProcessPriorityBoost,             // qs: ULONG
  ProcessDeviceMap,                 // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
  ProcessSessionInformation,        // q: PROCESS_SESSION_INFORMATION
  ProcessForegroundInformation,     // s: PROCESS_FOREGROUND_BACKGROUND
  ProcessWow64Information,          // q: ULONG_PTR
  ProcessImageFileName,             // q: UNICODE_STRING
  ProcessLUIDDeviceMapsEnabled,     // q: ULONG
  ProcessBreakOnTermination,        // qs: ULONG
  ProcessDebugObjectHandle,         // q: HANDLE // 30
  ProcessDebugFlags,                // qs: ULONG
  ProcessHandleTracing,  // q: PROCESS_HANDLE_TRACING_QUERY; s: PROCESS_HANDLE_TRACING_ENABLE[_EX] or void to disable
  ProcessIoPriority,     // qs: IO_PRIORITY_HINT
  ProcessExecuteFlags,   // qs: ULONG (MEM_EXECUTE_OPTION_*)
  ProcessTlsInformation, // PROCESS_TLS_INFORMATION // ProcessResourceManagement
  ProcessCookie,         // q: ULONG
  ProcessImageInformation,        // q: SECTION_IMAGE_INFORMATION
  ProcessCycleTime,               // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
  ProcessPagePriority,            // qs: PAGE_PRIORITY_INFORMATION
  ProcessInstrumentationCallback, // s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
  ProcessThreadStackAllocation,   // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
  ProcessWorkingSetWatchEx,       // q: PROCESS_WS_WATCH_INFORMATION_EX[]; s: void
  ProcessImageFileNameWin32,      // q: UNICODE_STRING
  ProcessImageFileMapping,        // q: HANDLE (input)
  ProcessAffinityUpdateMode,      // qs: PROCESS_AFFINITY_UPDATE_MODE
  ProcessMemoryAllocationMode,    // qs: PROCESS_MEMORY_ALLOCATION_MODE
  ProcessGroupInformation,        // q: USHORT[]
  ProcessTokenVirtualizationEnabled,      // s: ULONG
  ProcessConsoleHostProcess,              // qs: ULONG_PTR // ProcessOwnerInformation
  ProcessWindowInformation,               // q: PROCESS_WINDOW_INFORMATION // 50
  ProcessHandleInformation,               // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
  ProcessMitigationPolicy,                // s: PROCESS_MITIGATION_POLICY_INFORMATION
  ProcessDynamicFunctionTableInformation, // s: PROCESS_DYNAMIC_FUNCTION_TABLE_INFORMATION
  ProcessHandleCheckingMode,              // qs: ULONG; s: 0 disables, otherwise enables
  ProcessKeepAliveCount,                  // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
  ProcessRevokeFileHandles,               // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
  ProcessWorkingSetControl,               // s: PROCESS_WORKING_SET_CONTROL (requires SeDebugPrivilege)
  ProcessHandleTable,                     // q: ULONG[] // since WINBLUE
  ProcessCheckStackExtentsMode,           // qs: ULONG // KPROCESS->CheckStackExtents (CFG)
  ProcessCommandLineInformation,          // q: UNICODE_STRING // 60
  ProcessProtectionInformation,           // q: PS_PROTECTION
  ProcessMemoryExhaustion,                // s: PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
  ProcessFaultInformation,                // s: PROCESS_FAULT_INFORMATION
  ProcessTelemetryIdInformation,          // q: PROCESS_TELEMETRY_ID_INFORMATION
  ProcessCommitReleaseInformation,        // qs: PROCESS_COMMIT_RELEASE_INFORMATION
  ProcessDefaultCpuSetsInformation,       // qs: SYSTEM_CPU_SET_INFORMATION[5]
  ProcessAllowedCpuSetsInformation,       // qs: SYSTEM_CPU_SET_INFORMATION[5]
  ProcessSubsystemProcess,
  ProcessJobMemoryInformation,                 // q: PROCESS_JOB_MEMORY_INFO
  ProcessInPrivate,                            // q: BOOLEAN; s: void // ETW // since THRESHOLD2 // 70
  ProcessRaiseUMExceptionOnInvalidHandleClose, // qs: ULONG; s: 0 disables, otherwise enables
  ProcessIumChallengeResponse,
  ProcessChildProcessInformation,         // q: PROCESS_CHILD_PROCESS_INFORMATION
  ProcessHighGraphicsPriorityInformation, // qs: BOOLEAN (requires SeTcbPrivilege)
  ProcessSubsystemInformation,            // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
  ProcessEnergyValues,                    // q: PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
  ProcessPowerThrottlingState,            // qs: POWER_THROTTLING_PROCESS_STATE
  ProcessReserved3Information,            // ProcessActivityThrottlePolicy // PROCESS_ACTIVITY_THROTTLE_POLICY
  ProcessWin32kSyscallFilterInformation,  // q: WIN32K_SYSCALL_FILTER
  ProcessDisableSystemAllowedCpuSets,     // s: BOOLEAN // 80
  ProcessWakeInformation,                 // q: PROCESS_WAKE_INFORMATION
  ProcessEnergyTrackingState,             // qs: PROCESS_ENERGY_TRACKING_STATE
  ProcessManageWritesToExecutableMemory,  // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
  ProcessCaptureTrustletLiveDump,
  ProcessTelemetryCoverage, // q: TELEMETRY_COVERAGE_HEADER; s: TELEMETRY_COVERAGE_POINT
  ProcessEnclaveInformation,
  ProcessEnableReadWriteVmLogging,           // qs: PROCESS_READWRITEVM_LOGGING_INFORMATION
  ProcessUptimeInformation,                  // q: PROCESS_UPTIME_INFORMATION
  ProcessImageSection,                       // q: HANDLE
  ProcessDebugAuthInformation,               // since REDSTONE4 // 90
  ProcessSystemResourceManagement,           // s: PROCESS_SYSTEM_RESOURCE_MANAGEMENT
  ProcessSequenceNumber,                     // q: ULONGLONG
  ProcessLoaderDetour,                       // since REDSTONE5
  ProcessSecurityDomainInformation,          // q: PROCESS_SECURITY_DOMAIN_INFORMATION
  ProcessCombineSecurityDomainsInformation,  // s: PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
  ProcessEnableLogging,                      // qs: PROCESS_LOGGING_INFORMATION
  ProcessLeapSecondInformation,              // qs: PROCESS_LEAP_SECOND_INFORMATION
  ProcessFiberShadowStackAllocation,         // s: PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
  ProcessFreeFiberShadowStackAllocation,     // s: PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
  ProcessAltSystemCallInformation,           // s: PROCESS_SYSCALL_PROVIDER_INFORMATION // since 20H1 // 100
  ProcessDynamicEHContinuationTargets,       // s: PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
  ProcessDynamicEnforcedCetCompatibleRanges, // s: PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION // since 20H2
  ProcessCreateStateChange,                  // since WIN11
  ProcessApplyStateChange,
  ProcessEnableOptionalXStateFeatures, // s: ULONG64 // optional XState feature bitmask
  ProcessAltPrefetchParam,             // qs: OVERRIDE_PREFETCH_PARAMETER // App Launch Prefetch (ALPF) // since 22H1
  ProcessAssignCpuPartitions,
  ProcessPriorityClassEx,       // s: PROCESS_PRIORITY_CLASS_EX
  ProcessMembershipInformation, // q: PROCESS_MEMBERSHIP_INFORMATION
  ProcessEffectiveIoPriority,   // q: IO_PRIORITY_HINT // 110
  ProcessEffectivePagePriority, // q: ULONG
  ProcessSchedulerSharedData,   // since 24H2
  ProcessSlistRollbackInformation,
  ProcessNetworkIoCounters,         // q: PROCESS_NETWORK_COUNTERS
  ProcessFindFirstThreadByTebValue, // PROCESS_TEB_VALUE_INFORMATION
  MaxProcessInfoClass
};

typedef enum _MEMORY_INFORMATION_CLASS {
  MemoryBasicInformation,              // q: MEMORY_BASIC_INFORMATION
  MemoryWorkingSetInformation,         // q: MEMORY_WORKING_SET_INFORMATION
  MemoryMappedFilenameInformation,     // q: UNICODE_STRING
  MemoryRegionInformation,             // q: MEMORY_REGION_INFORMATION
  MemoryWorkingSetExInformation,       // q: MEMORY_WORKING_SET_EX_INFORMATION // since VISTA
  MemorySharedCommitInformation,       // q: MEMORY_SHARED_COMMIT_INFORMATION // since WIN8
  MemoryImageInformation,              // q: MEMORY_IMAGE_INFORMATION
  MemoryRegionInformationEx,           // MEMORY_REGION_INFORMATION
  MemoryPrivilegedBasicInformation,    // MEMORY_BASIC_INFORMATION
  MemoryEnclaveImageInformation,       // MEMORY_ENCLAVE_IMAGE_INFORMATION // since REDSTONE3
  MemoryBasicInformationCapped,        // 10
  MemoryPhysicalContiguityInformation, // MEMORY_PHYSICAL_CONTIGUITY_INFORMATION // since 20H1
  MemoryBadInformation,                // since WIN11
  MemoryBadInformationAllProcesses,    // since 22H1
  MemoryImageExtensionInformation,     // since 24H2
  MaxMemoryInfoClass
} MEMORY_INFORMATION_CLASS;

using SYSTEM_INFORMATION_CLASS = enum _SYSTEM_INFORMATION_CLASS {
  SystemBasicInformation,                // q: SYSTEM_BASIC_INFORMATION
  SystemProcessorInformation,            // q: SYSTEM_PROCESSOR_INFORMATION
  SystemPerformanceInformation,          // q: SYSTEM_PERFORMANCE_INFORMATION
  SystemTimeOfDayInformation,            // q: SYSTEM_TIMEOFDAY_INFORMATION
  SystemPathInformation,                 // not implemented
  SystemProcessInformation,              // q: SYSTEM_PROCESS_INFORMATION
  SystemCallCountInformation,            // q: SYSTEM_CALL_COUNT_INFORMATION
  SystemDeviceInformation,               // q: SYSTEM_DEVICE_INFORMATION
  SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION (EX in: USHORT ProcessorGroup)
  SystemFlagsInformation,                // q: SYSTEM_FLAGS_INFORMATION
  SystemCallTimeInformation,             // not implemented // SYSTEM_CALL_TIME_INFORMATION // 10
  SystemModuleInformation,               // q: RTL_PROCESS_MODULES
  SystemLocksInformation,                // q: RTL_PROCESS_LOCKS
  SystemStackTraceInformation,           // q: RTL_PROCESS_BACKTRACES
  SystemPagedPoolInformation,            // not implemented
  SystemNonPagedPoolInformation,         // not implemented
  SystemHandleInformation,               // q: SYSTEM_HANDLE_INFORMATION
  SystemObjectInformation,               // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
  SystemPageFileInformation,             // q: SYSTEM_PAGEFILE_INFORMATION
  SystemVdmInstemulInformation,          // q: SYSTEM_VDM_INSTEMUL_INFO
  SystemVdmBopInformation,               // not implemented // 20
  SystemFileCacheInformation,
  // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
  SystemPoolTagInformation,   // q: SYSTEM_POOLTAG_INFORMATION
  SystemInterruptInformation, // q: SYSTEM_INTERRUPT_INFORMATION (EX in: USHORT ProcessorGroup)
  SystemDpcBehaviorInformation,
  // q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
  SystemFullMemoryInformation,      // not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
  SystemLoadGdiDriverInformation,   // s (kernel-mode only)
  SystemUnloadGdiDriverInformation, // s (kernel-mode only)
  SystemTimeAdjustmentInformation,
  // q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
  SystemSummaryMemoryInformation, // not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
  SystemMirrorMemoryInformation,
  // s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege) // 30
  SystemPerformanceTraceInformation,   // q; s: (type depends on EVENT_TRACE_INFORMATION_CLASS)
  SystemObsolete0,                     // not implemented
  SystemExceptionInformation,          // q: SYSTEM_EXCEPTION_INFORMATION
  SystemCrashDumpStateInformation,     // s: SYSTEM_CRASH_DUMP_STATE_INFORMATION (requires SeDebugPrivilege)
  SystemKernelDebuggerInformation,     // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
  SystemContextSwitchInformation,      // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
  SystemRegistryQuotaInformation,      // q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
  SystemExtendServiceTableInformation, // s (requires SeLoadDriverPrivilege) // loads win32k only
  SystemPrioritySeperation,            // s (requires SeTcbPrivilege)
  SystemVerifierAddDriverInformation,  // s (requires SeDebugPrivilege) // 40
  SystemVerifierRemoveDriverInformation, // s (requires SeDebugPrivilege)
  SystemProcessorIdleInformation,        // q: SYSTEM_PROCESSOR_IDLE_INFORMATION (EX in: USHORT ProcessorGroup)
  SystemLegacyDriverInformation,         // q: SYSTEM_LEGACY_DRIVER_INFORMATION
  SystemCurrentTimeZoneInformation,      // q; s: RTL_TIME_ZONE_INFORMATION
  SystemLookasideInformation,            // q: SYSTEM_LOOKASIDE_INFORMATION
  SystemTimeSlipNotification,            // s: HANDLE (NtCreateEvent) (requires SeSystemtimePrivilege)
  SystemSessionCreate,                   // not implemented
  SystemSessionDetach,                   // not implemented
  SystemSessionInformation,              // not implemented (SYSTEM_SESSION_INFORMATION)
  SystemRangeStartInformation,           // q: SYSTEM_RANGE_START_INFORMATION // 50
  SystemVerifierInformation,             // q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
  SystemVerifierThunkExtend,             // s (kernel-mode only)
  SystemSessionProcessInformation,       // q: SYSTEM_SESSION_PROCESS_INFORMATION
  SystemLoadGdiDriverInSystemSpace,
  // s: SYSTEM_GDI_DRIVER_INFORMATION (kernel-mode only) (same as SystemLoadGdiDriverInformation)
  SystemNumaProcessorMap,               // q: SYSTEM_NUMA_INFORMATION
  SystemPrefetcherInformation,          // q; s: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
  SystemExtendedProcessInformation,     // q: SYSTEM_PROCESS_INFORMATION
  SystemRecommendedSharedDataAlignment, // q: ULONG // KeGetRecommendedSharedDataAlignment
  SystemComPlusPackage,                 // q; s: ULONG
  SystemNumaAvailableMemory,            // q: SYSTEM_NUMA_INFORMATION // 60
  SystemProcessorPowerInformation,      // q: SYSTEM_PROCESSOR_POWER_INFORMATION (EX in: USHORT ProcessorGroup)
  SystemEmulationBasicInformation,      // q: SYSTEM_BASIC_INFORMATION
  SystemEmulationProcessorInformation,  // q: SYSTEM_PROCESSOR_INFORMATION
  SystemExtendedHandleInformation,      // q: SYSTEM_HANDLE_INFORMATION_EX
  SystemLostDelayedWriteInformation,    // q: ULONG
  SystemBigPoolInformation,             // q: SYSTEM_BIGPOOL_INFORMATION
  SystemSessionPoolTagInformation,      // q: SYSTEM_SESSION_POOLTAG_INFORMATION
  SystemSessionMappedViewInformation,   // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
  SystemHotpatchInformation,            // q; s: SYSTEM_HOTPATCH_CODE_INFORMATION
  SystemObjectSecurityMode,             // q: ULONG // 70
  SystemWatchdogTimerHandler,           // s: SYSTEM_WATCHDOG_HANDLER_INFORMATION // (kernel-mode only)
  SystemWatchdogTimerInformation,       // q: SYSTEM_WATCHDOG_TIMER_INFORMATION // (kernel-mode only)
  SystemLogicalProcessorInformation,    // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION (EX in: USHORT ProcessorGroup)
  SystemWow64SharedInformationObsolete, // not implemented
  SystemRegisterFirmwareTableInformationHandler, // s: SYSTEM_FIRMWARE_TABLE_HANDLER // (kernel-mode only)
  SystemFirmwareTableInformation,                // SYSTEM_FIRMWARE_TABLE_INFORMATION
  SystemModuleInformationEx,                     // q: RTL_PROCESS_MODULE_INFORMATION_EX
  SystemVerifierTriageInformation,               // not implemented
  SystemSuperfetchInformation,                   // q; s: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
  SystemMemoryListInformation,
  // q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege) // 80
  SystemFileCacheInformationEx,
  // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
  SystemThreadPriorityClientIdInformation,
  // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege)
  SystemProcessorIdleCycleTimeInformation,
  // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup)
  SystemVerifierCancellationInformation,
  // SYSTEM_VERIFIER_CANCELLATION_INFORMATION // name:wow64:whNT32QuerySystemVerifierCancellationInformation
  SystemProcessorPowerInformationEx, // not implemented
  SystemRefTraceInformation,         // q; s: SYSTEM_REF_TRACE_INFORMATION // ObQueryRefTraceInformation
  SystemSpecialPoolInformation,
  // q; s: SYSTEM_SPECIAL_POOL_INFORMATION (requires SeDebugPrivilege) // MmSpecialPoolTag, then
  // MmSpecialPoolCatchOverruns != 0
  SystemProcessIdInformation,       // q: SYSTEM_PROCESS_ID_INFORMATION
  SystemErrorPortInformation,       // s (requires SeTcbPrivilege)
  SystemBootEnvironmentInformation, // q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION // 90
  SystemHypervisorInformation,      // q: SYSTEM_HYPERVISOR_QUERY_INFORMATION
  SystemVerifierInformationEx,      // q; s: SYSTEM_VERIFIER_INFORMATION_EX
  SystemTimeZoneInformation,        // q; s: RTL_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
  SystemImageFileExecutionOptionsInformation,
  // s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
  SystemCoverageInformation,
  // q: COVERAGE_MODULES s: COVERAGE_MODULE_REQUEST // ExpCovQueryInformation (requires SeDebugPrivilege)
  SystemPrefetchPatchInformation,   // SYSTEM_PREFETCH_PATCH_INFORMATION
  SystemVerifierFaultsInformation,  // s: SYSTEM_VERIFIER_FAULTS_INFORMATION (requires SeDebugPrivilege)
  SystemSystemPartitionInformation, // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
  SystemSystemDiskInformation,      // q: SYSTEM_SYSTEM_DISK_INFORMATION
  SystemProcessorPerformanceDistribution,
  // q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION (EX in: USHORT ProcessorGroup) // 100
  SystemNumaProximityNodeInformation,        // q; s: SYSTEM_NUMA_PROXIMITY_MAP
  SystemDynamicTimeZoneInformation,          // q; s: RTL_DYNAMIC_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
  SystemCodeIntegrityInformation,            // q: SYSTEM_CODEINTEGRITY_INFORMATION // SeCodeIntegrityQueryInformation
  SystemProcessorMicrocodeUpdateInformation, // s: SYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION
  SystemProcessorBrandString, // q: CHAR[] // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
  SystemVirtualAddressInformation,
  // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) //
  // MmQuerySystemVaInformation
  SystemLogicalProcessorAndGroupInformation,
  // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX (EX in: LOGICAL_PROCESSOR_RELATIONSHIP RelationshipType) // since WIN7
  // // KeQueryLogicalProcessorRelationship
  SystemProcessorCycleTimeInformation, // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup)
  SystemStoreInformation,
  // q; s: SYSTEM_STORE_INFORMATION (requires SeProfileSingleProcessPrivilege) // SmQueryStoreInformation
  SystemRegistryAppendString,        // s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS // 110
  SystemAitSamplingValue,            // s: ULONG (requires SeProfileSingleProcessPrivilege)
  SystemVhdBootInformation,          // q: SYSTEM_VHD_BOOT_INFORMATION
  SystemCpuQuotaInformation,         // q; s: PS_CPU_QUOTA_QUERY_INFORMATION
  SystemNativeBasicInformation,      // q: SYSTEM_BASIC_INFORMATION
  SystemErrorPortTimeouts,           // SYSTEM_ERROR_PORT_TIMEOUTS
  SystemLowPriorityIoInformation,    // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
  SystemTpmBootEntropyInformation,   // q: TPM_BOOT_ENTROPY_NT_RESULT // ExQueryTpmBootEntropyInformation
  SystemVerifierCountersInformation, // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
  SystemPagedPoolInformationEx,
  // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
  SystemSystemPtesInformationEx,
  // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) // 120
  SystemNodeDistanceInformation, // q: USHORT[4*NumaNodes] // (EX in: USHORT NodeNumber)
  SystemAcpiAuditInformation,
  // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
  SystemBasicPerformanceInformation,
  // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION //
  // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
  SystemQueryPerformanceCounterInformation, // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
  SystemSessionBigPoolInformation,          // q: SYSTEM_SESSION_POOLTAG_INFORMATION // since WIN8
  SystemBootGraphicsInformation,            // q; s: SYSTEM_BOOT_GRAPHICS_INFORMATION (kernel-mode only)
  SystemScrubPhysicalMemoryInformation,     // q; s: MEMORY_SCRUB_INFORMATION
  SystemBadPageInformation,                 // SYSTEM_BAD_PAGE_INFORMATION
  SystemProcessorProfileControlArea,        // q; s: SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA
  SystemCombinePhysicalMemoryInformation,
  // s: MEMORY_COMBINE_INFORMATION, MEMORY_COMBINE_INFORMATION_EX, MEMORY_COMBINE_INFORMATION_EX2 // 130
  SystemEntropyInterruptTimingInformation,   // q; s: SYSTEM_ENTROPY_TIMING_INFORMATION
  SystemConsoleInformation,                  // q; s: SYSTEM_CONSOLE_INFORMATION
  SystemPlatformBinaryInformation,           // q: SYSTEM_PLATFORM_BINARY_INFORMATION (requires SeTcbPrivilege)
  SystemPolicyInformation,                   // q: SYSTEM_POLICY_INFORMATION (Warbird/Encrypt/Decrypt/Execute)
  SystemHypervisorProcessorCountInformation, // q: SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
  SystemDeviceDataInformation,               // q: SYSTEM_DEVICE_DATA_INFORMATION
  SystemDeviceDataEnumerationInformation,    // q: SYSTEM_DEVICE_DATA_INFORMATION
  SystemMemoryTopologyInformation,           // q: SYSTEM_MEMORY_TOPOLOGY_INFORMATION
  SystemMemoryChannelInformation,            // q: SYSTEM_MEMORY_CHANNEL_INFORMATION
  SystemBootLogoInformation,                 // q: SYSTEM_BOOT_LOGO_INFORMATION // 140
  SystemProcessorPerformanceInformationEx,
  // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // (EX in: USHORT ProcessorGroup) // since WINBLUE
  SystemCriticalProcessErrorLogInformation,
  SystemSecureBootPolicyInformation, // q: SYSTEM_SECUREBOOT_POLICY_INFORMATION
  SystemPageFileInformationEx,       // q: SYSTEM_PAGEFILE_INFORMATION_EX
  SystemSecureBootInformation,       // q: SYSTEM_SECUREBOOT_INFORMATION
  SystemEntropyInterruptTimingRawInformation,
  SystemPortableWorkspaceEfiLauncherInformation, // q: SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
  SystemFullProcessInformation,
  // q: SYSTEM_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
  SystemKernelDebuggerInformationEx,       // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
  SystemBootMetadataInformation,           // 150
  SystemSoftRebootInformation,             // q: ULONG
  SystemElamCertificateInformation,        // s: SYSTEM_ELAM_CERTIFICATE_INFORMATION
  SystemOfflineDumpConfigInformation,      // q: OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2
  SystemProcessorFeaturesInformation,      // q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
  SystemRegistryReconciliationInformation, // s: NULL (requires admin) (flushes registry hives)
  SystemEdidInformation,                   // q: SYSTEM_EDID_INFORMATION
  SystemManufacturingInformation,          // q: SYSTEM_MANUFACTURING_INFORMATION // since THRESHOLD
  SystemEnergyEstimationConfigInformation, // q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
  SystemHypervisorDetailInformation,       // q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
  SystemProcessorCycleStatsInformation,
  // q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION (EX in: USHORT ProcessorGroup) // 160
  SystemVmGenerationCountInformation,
  SystemTrustedPlatformModuleInformation, // q: SYSTEM_TPM_INFORMATION
  SystemKernelDebuggerFlags,              // SYSTEM_KERNEL_DEBUGGER_FLAGS
  SystemCodeIntegrityPolicyInformation,   // q; s: SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
  SystemIsolatedUserModeInformation,      // q: SYSTEM_ISOLATED_USER_MODE_INFORMATION
  SystemHardwareSecurityTestInterfaceResultsInformation,
  SystemSingleModuleInformation,   // q: SYSTEM_SINGLE_MODULE_INFORMATION
  SystemAllowedCpuSetsInformation, // s: SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION
  SystemVsmProtectionInformation,  // q: SYSTEM_VSM_PROTECTION_INFORMATION (previously SystemDmaProtectionInformation)
  SystemInterruptCpuSetsInformation,     // q: SYSTEM_INTERRUPT_CPU_SET_INFORMATION // 170
  SystemSecureBootPolicyFullInformation, // q: SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
  SystemCodeIntegrityPolicyFullInformation,
  SystemAffinitizedInterruptProcessorInformation, // (requires SeIncreaseBasePriorityPrivilege)
  SystemRootSiloInformation,                      // q: SYSTEM_ROOT_SILO_INFORMATION
  SystemCpuSetInformation,                        // q: SYSTEM_CPU_SET_INFORMATION // since THRESHOLD2
  SystemCpuSetTagInformation,                     // q: SYSTEM_CPU_SET_TAG_INFORMATION
  SystemWin32WerStartCallout,
  SystemSecureKernelProfileInformation, // q: SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
  SystemCodeIntegrityPlatformManifestInformation,
  // q: SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION // since REDSTONE
  SystemInterruptSteeringInformation,
  // q: in: SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT, out: SYSTEM_INTERRUPT_STEERING_INFORMATION_OUTPUT //
  // NtQuerySystemInformationEx // 180
  SystemSupportedProcessorArchitectures,
  // p: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx
  SystemMemoryUsageInformation,              // q: SYSTEM_MEMORY_USAGE_INFORMATION
  SystemCodeIntegrityCertificateInformation, // q: SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
  SystemPhysicalMemoryInformation,           // q: SYSTEM_PHYSICAL_MEMORY_INFORMATION // since REDSTONE2
  SystemControlFlowTransition,               // (Warbird/Encrypt/Decrypt/Execute)
  SystemKernelDebuggingAllowed,              // s: ULONG
  SystemActivityModerationExeState,          // SYSTEM_ACTIVITY_MODERATION_EXE_STATE
  SystemActivityModerationUserSettings,      // SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS
  SystemCodeIntegrityPoliciesFullInformation,
  SystemCodeIntegrityUnlockInformation, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION // 190
  SystemIntegrityQuotaInformation,
  SystemFlushInformation,             // q: SYSTEM_FLUSH_INFORMATION
  SystemProcessorIdleMaskInformation, // q: ULONG_PTR[ActiveGroupCount] // since REDSTONE3
  SystemSecureDumpEncryptionInformation,
  SystemWriteConstraintInformation,      // SYSTEM_WRITE_CONSTRAINT_INFORMATION
  SystemKernelVaShadowInformation,       // SYSTEM_KERNEL_VA_SHADOW_INFORMATION
  SystemHypervisorSharedPageInformation, // SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION // since REDSTONE4
  SystemFirmwareBootPerformanceInformation,
  SystemCodeIntegrityVerificationInformation, // SYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION
  SystemFirmwarePartitionInformation,         // SYSTEM_FIRMWARE_PARTITION_INFORMATION // 200
  SystemSpeculationControlInformation,
  // SYSTEM_SPECULATION_CONTROL_INFORMATION // (CVE-2017-5715) REDSTONE3 and above.
  SystemDmaGuardPolicyInformation,          // SYSTEM_DMA_GUARD_POLICY_INFORMATION
  SystemEnclaveLaunchControlInformation,    // SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION
  SystemWorkloadAllowedCpuSetsInformation,  // SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION // since REDSTONE5
  SystemCodeIntegrityUnlockModeInformation, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION
  SystemLeapSecondInformation,              // SYSTEM_LEAP_SECOND_INFORMATION
  SystemFlags2Information,                  // q: SYSTEM_FLAGS_INFORMATION
  SystemSecurityModelInformation,           // SYSTEM_SECURITY_MODEL_INFORMATION // since 19H1
  SystemCodeIntegritySyntheticCacheInformation,
  SystemFeatureConfigurationInformation,
  // q: in: SYSTEM_FEATURE_CONFIGURATION_QUERY, out: SYSTEM_FEATURE_CONFIGURATION_INFORMATION; s:
  // SYSTEM_FEATURE_CONFIGURATION_UPDATE // NtQuerySystemInformationEx // since 20H1 // 210
  SystemFeatureConfigurationSectionInformation,
  // q: in: SYSTEM_FEATURE_CONFIGURATION_SECTIONS_REQUEST, out: SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION //
  // NtQuerySystemInformationEx
  SystemFeatureUsageSubscriptionInformation,
  // q: SYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS; s: SYSTEM_FEATURE_USAGE_SUBSCRIPTION_UPDATE
  SystemSecureSpeculationControlInformation, // SECURE_SPECULATION_CONTROL_INFORMATION
  SystemSpacesBootInformation,               // since 20H2
  SystemFwRamdiskInformation,                // SYSTEM_FIRMWARE_RAMDISK_INFORMATION
  SystemWheaIpmiHardwareInformation,
  SystemDifSetRuleClassInformation, // SYSTEM_DIF_VOLATILE_INFORMATION
  SystemDifClearRuleClassInformation,
  SystemDifApplyPluginVerificationOnDriver,  // SYSTEM_DIF_PLUGIN_DRIVER_INFORMATION
  SystemDifRemovePluginVerificationOnDriver, // SYSTEM_DIF_PLUGIN_DRIVER_INFORMATION // 220
  SystemShadowStackInformation,              // SYSTEM_SHADOW_STACK_INFORMATION
  SystemBuildVersionInformation,
  // q: in: ULONG (LayerNumber), out: SYSTEM_BUILD_VERSION_INFORMATION // NtQuerySystemInformationEx // 222
  SystemPoolLimitInformation, // SYSTEM_POOL_LIMIT_INFORMATION (requires SeIncreaseQuotaPrivilege)
  SystemCodeIntegrityAddDynamicStore,
  SystemCodeIntegrityClearDynamicStores,
  SystemDifPoolTrackingInformation,
  SystemPoolZeroingInformation,  // q: SYSTEM_POOL_ZEROING_INFORMATION
  SystemDpcWatchdogInformation,  // q; s: SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION
  SystemDpcWatchdogInformation2, // q; s: SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION_V2
  SystemSupportedProcessorArchitectures2,
  // q: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx //
  // 230
  SystemSingleProcessorRelationshipInformation,
  // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // (EX in: PROCESSOR_NUMBER Processor)
  SystemXfgCheckFailureInformation,     // q: SYSTEM_XFG_FAILURE_INFORMATION
  SystemIommuStateInformation,          // SYSTEM_IOMMU_STATE_INFORMATION // since 22H1
  SystemHypervisorMinrootInformation,   // SYSTEM_HYPERVISOR_MINROOT_INFORMATION
  SystemHypervisorBootPagesInformation, // SYSTEM_HYPERVISOR_BOOT_PAGES_INFORMATION
  SystemPointerAuthInformation,         // SYSTEM_POINTER_AUTH_INFORMATION
  SystemSecureKernelDebuggerInformation,
  SystemOriginalImageFeatureInformation,
  // q: in: SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_INPUT, out: SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_OUTPUT //
  // NtQuerySystemInformationEx
  SystemMemoryNumaInformation, // SYSTEM_MEMORY_NUMA_INFORMATION_INPUT, SYSTEM_MEMORY_NUMA_INFORMATION_OUTPUT
  SystemMemoryNumaPerformanceInformation,
  // SYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_INPUTSYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_INPUT,
  // SYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_OUTPUT // since 24H2 // 240
  SystemCodeIntegritySignedPoliciesFullInformation,
  SystemSecureSecretsInformation,
  SystemTrustedAppsRuntimeInformation,          // SYSTEM_TRUSTEDAPPS_RUNTIME_INFORMATION
  SystemBadPageInformationEx,                   // SYSTEM_BAD_PAGE_INFORMATION
  SystemResourceDeadlockTimeout,                // ULONG
  SystemBreakOnContextUnwindFailureInformation, // ULONG (requires SeDebugPrivilege)
  SystemOslRamdiskInformation,                  // SYSTEM_OSL_RAMDISK_INFORMATION
  MaxSystemInfoClass
};