#pragma once

#define USE_CAPSTONE
#define STATE_TRACKING true
#define GET_OPERAND_MASK(x, y) uint64_t x = ( 1ULL << ( y * 8 ) ) - 1; if ( y == 8 ) {x = 0xFFFFFFFFFFFFFFFFULL;}

#include <shared/capstone++.hpp>
#include <shared/portable_executable.hpp>
#include <shared/types.hpp>


template<typename T = void>
concept X64MODE = ( sizeof ( void* ) == 8 );

extern std::unique_ptr<PE::Parser> parser;
struct EmulationContext;

struct EmuOptions {
	uint8_t allow_reserved_write : 1;
	uint8_t enable_logging : 1;
	uint8_t exit_on_infinite_loop : 1;
	uint8_t reserved : 5;
};

using Handler = std::function<void ( capstone::Instruction&, EmulationContext&, InstructionEffect& )>;
using APIHandler = std::function<void ( capstone::Instruction&, EmulationContext&, InstructionEffect&, uint64_t )>;
using ImportHandler = std::function<void ( capstone::Instruction&, EmulationContext&, InstructionEffect& )>;

enum class Platform : uint64_t {
	WINDOWS = 0,
	LINUX = 1
};

struct alignas( 64 ) KCPU {
	/* HOT */
	CPUFlags cpu_flags {};
	std::array<uint64_t, KGPR_COUNT> registers;
	int64_t rsp_offset = 0;
	uint64_t tsc = 0;
	/* COLD */
	FPUStack fpu {};
	uint8_t current_privilege_level = 3;
	std::unique_ptr<std::array<uint512_t, 16>> avx_registers; // we need this because of the size, it will ruin cache locality

};

struct alignas( 64 ) WindowsCompat {
	std::unordered_map<uint64_t, std::pair<std::string, std::string>> imports;
	std::unordered_map<uint64_t, std::vector<uint64_t>> memory_writes;
	std::unordered_map<std::string, ImportHandler> import_handlers;
	std::unordered_map<uint64_t, APIHandler> api_hooks;
	std::map<uint16_t, uint64_t> io_ports;
	std::multimap<std::string, uint64_t> import_multi_map;
	HMODULE loaded_module = nullptr;
	uint64_t loaded_base_address = 0;
	uint64_t loaded_module_size = 0;

	uint64_t ntdll_base = 0;
	uint64_t kernel32_base = 0;
	uint64_t ldr_initialize_thunk = 0;
	uint64_t rtl_user_thread_start = 0;
	uint64_t ki_user_apc_dispatcher = 0;
	uint64_t ki_user_exception_dispatcher = 0;

	std::unique_ptr<_TEB64> teb = nullptr;

	std::unordered_map<uint64_t, LoadedModule> loaded_modules;
	uint64_t current_module_base = 0;

	void add_module ( HMODULE handle, uint64_t base, uint64_t size, const uint8_t* code ) {
		loaded_modules [ base ] = LoadedModule {
			.handle = handle,
			.base_address = base,
			.size = size,
			.decoder = std::make_unique<capstone::Decoder> ( code, size, base )
		};
		if ( !loaded_base_address ) {
			loaded_module = handle;
			loaded_base_address = base;
			loaded_module_size = size;
		}
	}
};

struct EmulationContext {
	EmulationContext ( );
	std::unique_ptr<KCPU> cpu;
	std::unique_ptr<WindowsCompat> windows;
	Platform host_os = Platform::WINDOWS;

	std::vector<capstone::Decoder*> decoder;

	/* metadata */

	bool exit_due_to_critical_error = false;
	bool exit_due_to_termination = false;

	/* Windows structures */

	/* Timing */
	void increment_tsc ( );

	std::string console_output;

	/* Module */
	void initialize_imports ( std::unique_ptr<PE::Parser>& parser );

	/* Stack */
	std::unique_ptr<uint8_t [ ], void( * )( uint8_t* )> rsp_base = { nullptr, [ ] ( uint8_t* ) { } };
	int64_t stack_allocated = 0x200000;

	/* Call Frames */
	std::vector<CallFrame> call_stack;
	void push_call_frame ( uint64_t ret_addr, InstructionEffect& effect );
	void pop_call_frame ( InstructionEffect& effect );

	/* State */
	EmuOptions options {
		.allow_reserved_write = false,
		.enable_logging = false,
		.exit_on_infinite_loop = true
	};

	/* Checks */
	bool is_within_stack_bounds ( uint64_t address, uint8_t size ) const noexcept;

	/* Getters & Setters */
	uint64_t get_access_mask ( x86_reg reg, uint8_t size ) const noexcept;
	uint8_t get_access_shift ( x86_reg reg, uint8_t size ) const noexcept;
	uint32_t get_eflags ( ) const noexcept;
	uint64_t get_rflags ( ) const noexcept;
	void set_eflags ( uint32_t rflags, InstructionEffect& effect ) noexcept;
	void set_rflags ( uint64_t rflags, InstructionEffect& effect ) noexcept;

	uint64_t get_reg ( x86_reg reg, uint8_t size = 8 ) const;
	uint64_t get_stack ( uint64_t address, uint8_t size = 8 ) const;
	uint128_t get_stack_128 ( uint64_t address ) const;
	uint64_t get_memory ( uint64_t addr, uint8_t size = 8 ) const;
	void allocate_kuser_shared_data ( InstructionEffect& effect );
	void set_rcx_to_ioport ( uint16_t port, InstructionEffect& effect );

	template <typename T>
	const T& get_reg ( x86_reg reg ) const;

	template <typename T>
	T& get_reg_mut ( x86_reg reg );

	uint128_t get_xmm_raw ( x86_reg reg ) const;
	void set_xmm_raw ( x86_reg reg, const uint128_t& value, InstructionEffect& effect );

	uint256_t get_ymm_raw ( x86_reg reg ) const;
	void set_ymm_raw ( x86_reg reg, const uint256_t& value, InstructionEffect& effect );

	uint512_t get_zmm_raw ( x86_reg reg ) const;
	void set_zmm_raw ( x86_reg reg, const uint512_t& value, InstructionEffect& effect );

	float get_xmm_float ( x86_reg reg ) const;
	void set_xmm_float ( x86_reg reg, float value, InstructionEffect& effect );

	double get_xmm_double ( x86_reg reg ) const;
	void set_xmm_double ( x86_reg reg, double value, InstructionEffect& effect );

	uint128_t get_memory_128 ( uint64_t addr ) const;
	void set_memory_128 ( uint64_t addr, const uint128_t& val, InstructionEffect& effect );

	uint256_t get_memory_256 ( uint64_t addr ) const;
	void set_memory_256 ( uint64_t addr, const uint256_t& val, InstructionEffect& effect );

	uint512_t get_memory_512 ( uint64_t addr ) const;
	void set_memory_512 ( uint64_t addr, const uint512_t& val, InstructionEffect& effect );

	void set_reg ( x86_reg reg, uint64_t val, uint8_t size, InstructionEffect& effect );
	void set_stack ( uint64_t offset, uint64_t val, InstructionEffect& effect, uint8_t size = 8 );
	void set_stack_128 ( uint64_t offset, uint128_t val, InstructionEffect& effect );
	void set_memory ( uint64_t addr, uint64_t val, uint8_t size, InstructionEffect& effect );

	void save_context ( CONTEXT* ms_context );
	/* Helpers */
	uint64_t translate_reg ( x86_reg reg, uint64_t value, uint8_t op_size ) const noexcept;
	x86_reg to_64bit_reg ( x86_reg reg ) const noexcept; // Helper to map sub-registers to their 64-bit parent for storage
	void dump_state ( ) const;
	bool is_string_at ( int64_t base, int64_t max_len ) const;
	void allocate_stack ( int64_t size, InstructionEffect& effect ) noexcept;

	/* State logging */
	InstructionEffect log_effect ( capstone::Instruction& instr );
	void log_reg_change ( InstructionEffect& effect, x86_reg reg, uint64_t old_val, uint64_t new_val, const char* op );
	void log_reg_change ( InstructionEffect& effect, x86_reg reg, int128_t old_val, int128_t new_val, const char* op );
	void log_flag_change ( InstructionEffect& effect, const char* flag, uint64_t old_val, uint64_t new_val );
	void log_rflags_changes ( uint64_t old_rflags, uint64_t new_rflags, InstructionEffect& effect ) noexcept;
	void log_stack_change ( InstructionEffect& effect, int64_t addr, uint64_t old_val, uint64_t new_val, uint8_t size = 8 );
	void log_mxcsr_flag_change ( InstructionEffect& effect, const char* flag_name, uint32_t old_val, uint32_t new_val );

	/* Update flags */
	void update_flags_add ( uint64_t a, uint64_t b, uint8_t op_size, InstructionEffect& effect );
	void update_flags_adc ( uint64_t a, uint64_t b, uint64_t carry, uint8_t op_size, InstructionEffect& effect );
	void update_flags_sub ( uint64_t a, uint64_t b, uint8_t op_size, InstructionEffect& effect );
	void update_flags_shl ( uint64_t val, uint64_t shift, uint8_t op_size, InstructionEffect& effect );
	void update_flags_sar ( uint64_t val, uint64_t shift, uint8_t op_size, InstructionEffect& effect );
	void update_flags_inc ( uint64_t val, uint8_t op_size, InstructionEffect& effect );
	void update_flags_dec ( uint64_t val, uint8_t op_size, InstructionEffect& effect );
	void update_flags_mul ( uint64_t a, uint64_t b, uint8_t op_size, InstructionEffect& effect );
	void update_flags_div ( uint64_t dividend, uint64_t divisor, uint8_t op_size, InstructionEffect& effect );
	void update_flags_and ( uint64_t a, uint64_t b, uint8_t op_size, InstructionEffect& effect );
	void update_flags_or ( uint64_t a, uint64_t b, uint8_t op_size, InstructionEffect& effect );
	void update_flags_xor ( uint64_t a, uint64_t b, uint8_t op_size, InstructionEffect& effect );
	void update_flags_not ( uint64_t val, uint8_t op_size, InstructionEffect& effect );
	void update_flags_shr ( uint64_t val, uint64_t shift, uint8_t op_size, InstructionEffect& effect );
	void update_flags_test ( uint64_t a, uint64_t b, uint8_t op_size, InstructionEffect& effect );

	template<std::floating_point T>
	void update_mxcsr_arithmetic ( T a, T b, T result, InstructionEffect& effect );
	template<std::floating_point T>
	void update_flags_for_compare ( T a, T b, bool is_unorderd_quiet, InstructionEffect& effect );
	template<std::floating_point F, typename I> // F = float/double, I = int32/int64
	void update_mxcsr_conversion_float_to_int ( F src, I dst, bool is_truncate, InstructionEffect& effect );
	template<typename I, std::floating_point F> // I = int32/int64, F = float/double
	void update_mxcsr_conversion_int_to_float ( I src, F dst, InstructionEffect& effect );
	void update_mxcsr_conversion ( float src, double dst, InstructionEffect& effect );
	void update_mxcsr_conversion ( double src, float dst, InstructionEffect& effect );
	template<std::floating_point T>
	void update_mxcsr_sqrt ( T src, T result, InstructionEffect& effect );

	/* Exception related */
	bool is_alignment_check_enabled ( ) const noexcept;
	static void initialize_exception_table ( ) noexcept;

	capstone::Decoder* get_decoder_for_address ( uint64_t addr ) {
		for ( const auto& [base, mod] : windows->loaded_modules ) {
			if ( addr >= base && addr < base + mod.size ) {
				return mod.decoder.get ( );
			}
		}
		return decoder.back ( ); // Fallback to default decoder
	}

	int get_fpu_phys_idx ( int sti ) const {
		return ( cpu->fpu.fpu_top + sti ) % 8;
	}
	void set_fpu_tag ( int phys_idx, uint8_t tag ) {
		int shift = phys_idx * 2;
		cpu->fpu.fpu_tag_word = ( cpu->fpu.fpu_tag_word & ~( 0b11 << shift ) ) | ( tag << shift );
	}
	uint8_t get_fpu_tag ( int phys_idx ) const {
		return ( cpu->fpu.fpu_tag_word >> ( phys_idx * 2 ) ) & 0b11;
	}
	void update_fsw_top ( ) {
		cpu->fpu.fpu_status_word = ( cpu->fpu.fpu_status_word & ~FSW_TOP_MASK ) | ( ( cpu->fpu.fpu_top & 0b111 ) << FSW_TOP_SHIFT );
	}

	// Checks determined FSW flags against FCW masks and raises OS exception if needed.
	void check_fpu_exception ( uint16_t determined_fsw_flags ) {
		cpu->fpu.fpu_status_word |= determined_fsw_flags; // Set determined flags in actual FSW

		// Check if any *unmasked* exception occurred
		bool unmasked_occurred = false;
		if ( ( determined_fsw_flags & FSW_IE ) && !( cpu->fpu.fpu_control_word & FCW_IM ) ) unmasked_occurred = true;
		if ( ( determined_fsw_flags & FSW_DE ) && !( cpu->fpu.fpu_control_word & FCW_DM ) ) unmasked_occurred = true;
		if ( ( determined_fsw_flags & FSW_ZE ) && !( cpu->fpu.fpu_control_word & FCW_ZM ) ) unmasked_occurred = true;
		if ( ( determined_fsw_flags & FSW_OE ) && !( cpu->fpu.fpu_control_word & FCW_OM ) ) unmasked_occurred = true;
		if ( ( determined_fsw_flags & FSW_UE ) && !( cpu->fpu.fpu_control_word & FCW_UM ) ) unmasked_occurred = true;
		if ( ( determined_fsw_flags & FSW_PE ) && !( cpu->fpu.fpu_control_word & FCW_PM ) ) unmasked_occurred = true;
		// Stack Fault (#IS involving stack) is generally unmaskable
		if ( determined_fsw_flags & FSW_SF ) unmasked_occurred = true;

		if ( unmasked_occurred ) {
			cpu->fpu.fpu_status_word |= FSW_ES; // Set Error Summary
			uint64_t faulting_rip = decoder.back ( )->last_successful_ip ( );
			std::println ( "!!!! Unmasked FPU Exception Flags: 0x{:04x} !!!!", determined_fsw_flags );

			// Map to Windows STATUS_FLOAT_* code
			DWORD win_code = EXCEPTION_FLT_INVALID_OPERATION; // Default
			if ( ( determined_fsw_flags & FSW_SF ) ) win_code = EXCEPTION_FLT_STACK_CHECK; // Map #IS Stack fault
			else if ( ( determined_fsw_flags & FSW_ZE ) && !( cpu->fpu.fpu_control_word & FCW_ZM ) ) win_code = EXCEPTION_FLT_DIVIDE_BY_ZERO;
			else if ( ( determined_fsw_flags & FSW_OE ) && !( cpu->fpu.fpu_control_word & FCW_OM ) ) win_code = EXCEPTION_FLT_OVERFLOW;
			else if ( ( determined_fsw_flags & FSW_UE ) && !( cpu->fpu.fpu_control_word & FCW_UM ) ) win_code = EXCEPTION_FLT_UNDERFLOW;
			else if ( ( determined_fsw_flags & FSW_DE ) && !( cpu->fpu.fpu_control_word & FCW_DM ) ) win_code = EXCEPTION_FLT_DENORMAL_OPERAND;
			else if ( ( determined_fsw_flags & FSW_PE ) && !( cpu->fpu.fpu_control_word & FCW_PM ) ) win_code = EXCEPTION_FLT_INEXACT_RESULT; // Often masked
			// Prioritize stack, then other specific unmasked flags, then general invalid

			GuestExceptionInfo ex;
			ex.set_exception ( win_code, faulting_rip );
			throw ex;
		}
	}
	uint8_t classify_fpu_operand ( const float80_t& val ) const {
		using namespace boost::multiprecision;
		int c = fpclassify ( val );
		switch ( c ) {
			case FP_NAN:       return FPU_TAG_SPECIAL;
			case FP_INFINITE:  return FPU_TAG_SPECIAL;
			case FP_ZERO:      return FPU_TAG_ZERO;
			case FP_SUBNORMAL: return FPU_TAG_SPECIAL; // Denormals treated as Special for tag
			case FP_NORMAL:    return FPU_TAG_VALID;
			default:           return FPU_TAG_SPECIAL; // Should not happen
		}
	}

	int get_std_rounding_mode ( ) const {
		int fcw_round = ( cpu->fpu.fpu_control_word & FCW_RC_MASK ) >> FCW_RC_SHIFT;
		switch ( fcw_round ) {
			case 0: return FE_TONEAREST;
			case 1: return FE_DOWNWARD;
			case 2: return FE_UPWARD;
			case 3: return FE_TOWARDZERO;
			default: return FE_TONEAREST;
		}
	}

	float80_t read_float80_from_memory ( uint64_t addr, InstructionEffect& effect );
	void write_float80_to_memory ( uint64_t addr, const float80_t& val, InstructionEffect& effect );
};


// Instruction Handlers
namespace handlers
{
	/* Data handlers */
	inline Handler mov = nullptr;
	inline Handler movsw = nullptr;
	inline Handler movsd = nullptr;
	inline Handler movsq = nullptr;
	inline Handler movabs = nullptr;
	inline Handler movaps = nullptr;
	inline Handler movzx = nullptr;
	inline Handler push = nullptr;
	inline Handler pushfq = nullptr;
	inline Handler pop = nullptr;
	inline Handler popfq = nullptr;
	inline Handler lea = nullptr;
	inline Handler movsx = nullptr;
	inline Handler sahf = nullptr;
	inline Handler lahf = nullptr;
	inline Handler movsxd = nullptr;
	inline Handler xchg = nullptr;
	inline Handler stos = nullptr;
	inline Handler punpcklqdq = nullptr;
	inline Handler prefetchw = nullptr;
	inline Handler psrldq = nullptr;

	/* Arithmetic handlers */

	inline Handler add = nullptr;
	inline Handler sub = nullptr;
	inline Handler inc = nullptr;
	inline Handler dec = nullptr;
	inline Handler mul = nullptr;
	inline Handler imul = nullptr;
	inline Handler div = nullptr;
	inline Handler idiv = nullptr;
	inline Handler cdq = nullptr;
	inline Handler cdqe = nullptr;
	inline Handler adc = nullptr;
	inline Handler neg = nullptr;
	inline Handler sbb = nullptr;



	/**** Float airthmetic */
	inline Handler movsb = nullptr;
	inline Handler movss = nullptr;
	inline Handler movq = nullptr;
	inline Handler movups = nullptr;
	inline Handler movdqu = nullptr;
	inline Handler addss = nullptr;
	inline Handler cmpss = nullptr;
	inline Handler mulss = nullptr;
	inline Handler divss = nullptr;
	inline Handler sqrtss = nullptr;
	inline Handler sqrtsd = nullptr;
	inline Handler cvtss2si = nullptr;
	inline Handler subss = nullptr;
	inline Handler minss = nullptr;
	inline Handler maxss = nullptr;
	inline Handler comiss = nullptr;
	inline Handler roundss = nullptr;
	inline Handler rcpss = nullptr;
	inline Handler rsqrtss = nullptr;
	inline Handler ucomiss = nullptr;
	inline Handler cvtsi2ss = nullptr;
	inline Handler cvttss2si = nullptr;
	inline Handler cvtss2sd = nullptr;
	inline Handler cvtsd2ss = nullptr;
	inline Handler andps = nullptr;
	inline Handler orps = nullptr;
	inline Handler xorps = nullptr;
	inline Handler movhlps = nullptr;
	inline Handler unpcklps = nullptr;
	inline Handler cvtsi2sd = nullptr;
	inline Handler mulsd = nullptr;
	inline Handler comisd = nullptr;

	inline Handler fld = nullptr;
	inline Handler fprem = nullptr;
	inline Handler fstp = nullptr;
	inline Handler ffree = nullptr;
	inline Handler fincstp = nullptr;
	inline Handler fmul = nullptr;
	inline Handler fmulp = nullptr;



	/* Logical handlers */
	inline Handler and_ = nullptr;
	inline Handler xadd = nullptr;
	inline Handler or_ = nullptr;
	inline Handler xor_ = nullptr;
	inline Handler not_ = nullptr;
	inline Handler shl = nullptr;
	inline Handler shld = nullptr;
	inline Handler shr = nullptr;
	inline Handler shrd = nullptr;
	inline Handler sar = nullptr;
	inline Handler sal = nullptr;
	inline Handler cmovo = nullptr;
	inline Handler cmovnl = nullptr;
	inline Handler cmovbe = nullptr;
	inline Handler cmovz = nullptr;
	inline Handler cmovle = nullptr;
	inline Handler cmovl = nullptr;
	inline Handler cmovnp = nullptr;
	inline Handler cmovns = nullptr;
	inline Handler cmovp = nullptr;
	inline Handler cmovnb = nullptr;
	inline Handler cmovno = nullptr;
	inline Handler cmovs = nullptr;
	inline Handler cmovnz = nullptr;
	inline Handler cmovnle = nullptr;
	inline Handler cmovnbe = nullptr;
	inline Handler cmovb = nullptr;
	inline Handler movlhps = nullptr;
	inline Handler rdrand = nullptr;

	/* Control-flow altering */
	inline Handler cmp = nullptr;
	inline Handler cmpxchg = nullptr;
	inline Handler cmpxchg16b = nullptr;
	inline Handler test = nullptr;
	inline Handler call = nullptr;
	inline Handler ret = nullptr;

	/* JX Handlers */
	inline Handler jmp = nullptr;
	inline Handler je = nullptr;
	inline Handler jnbe = nullptr;
	inline Handler jne = nullptr;
	inline Handler jg = nullptr;
	inline Handler jl = nullptr;
	inline Handler jnb = nullptr;
	inline Handler jb = nullptr;
	inline Handler jns = nullptr;
	inline Handler jnl = nullptr;
	inline Handler jo = nullptr;
	inline Handler jno = nullptr;
	inline Handler jbe = nullptr;
	inline Handler js = nullptr;
	inline Handler ja = nullptr;
	inline Handler jae = nullptr;
	inline Handler jge = nullptr;
	inline Handler jle = nullptr;
	inline Handler jp = nullptr;
	inline Handler jnp = nullptr;
	inline Handler jcxz = nullptr;
	inline Handler jecxz = nullptr;
	inline Handler jrcxz = nullptr;

	/* Function related */
	inline Handler enter = nullptr;
	inline Handler leave = nullptr;
	inline Handler nop = nullptr;

	/* Bit operations */
	inline Handler bzhi = nullptr;
	inline Handler andn = nullptr;
	inline Handler bextr = nullptr;
	inline Handler ror = nullptr;
	inline Handler rol = nullptr;
	inline Handler popcnt = nullptr;
	inline Handler tzcnt = nullptr;
	inline Handler bswap = nullptr;
	inline Handler bsr = nullptr;
	inline Handler setb = nullptr;
	inline Handler setbe = nullptr;
	inline Handler setnp = nullptr;
	inline Handler setnl = nullptr;
	inline Handler sets = nullptr;
	inline Handler seto = nullptr;
	inline Handler setz = nullptr;
	inline Handler setnb = nullptr;
	inline Handler setno = nullptr;
	inline Handler rcr = nullptr;
	inline Handler rcl = nullptr;
	inline Handler bt = nullptr;
	inline Handler bts = nullptr;
	inline Handler setp = nullptr;
	inline Handler setle = nullptr;
	inline Handler setnle = nullptr;
	inline Handler setns = nullptr;
	inline Handler setl = nullptr;
	inline Handler setnbe = nullptr;
	inline Handler setnz = nullptr;
	inline Handler cli = nullptr;
	inline Handler btr = nullptr;
	inline Handler cbw = nullptr;
	inline Handler cqo = nullptr;
	inline Handler btc = nullptr;
	inline Handler cwd = nullptr;
	inline Handler cwde = nullptr;
	inline Handler cld = nullptr;
	inline Handler clc = nullptr;
	inline Handler clui = nullptr;
	inline Handler cmc = nullptr;
	inline Handler stc = nullptr;
	inline Handler bsf = nullptr;

	/* AVX */
	inline Handler vpxor = nullptr;
	inline Handler vpcmpeqw = nullptr;
	inline Handler vpmovmskb = nullptr;
	inline Handler vzeroupper = nullptr;
	inline Handler vinsertf128 = nullptr;
	inline Handler vmovups = nullptr;
	inline Handler vmovaps = nullptr;
	inline Handler vmovdqu = nullptr;

	/* Other */
	inline Handler rdtsc = nullptr;
	inline Handler cpuid = nullptr;
	inline Handler xgetbv = nullptr;
	inline Handler syscall = nullptr;
	inline Handler bound = nullptr;
	inline Handler hlt = nullptr;
	inline Handler stmxcsr = nullptr;
	inline Handler ldmxcsr = nullptr;
	inline Handler fnstcw = nullptr;
	inline Handler int_ = nullptr;
	inline Handler int1 = nullptr;
	inline Handler int3 = nullptr;
	inline Handler fxsave = nullptr;
	inline Handler fxrstor = nullptr;

	/* IO */
	inline Handler io_in = nullptr;
	inline Handler io_out = nullptr;
	inline Handler outx = nullptr;

	namespace winapi
	{
		inline APIHandler forward = nullptr;

		/* Processor related */
		inline APIHandler IsProcessorFeaturePresent = nullptr;

		/* Module related*/
		inline APIHandler LoadLibraryA = nullptr;
		inline APIHandler LoadLibraryW = nullptr;
		inline APIHandler LoadLibraryExA = nullptr;
		inline APIHandler LoadLibraryExW = nullptr;

		/* Procedure related */
		inline APIHandler GetProcAddress = nullptr;

		/* Critical sections */
		inline APIHandler InitializeCriticalSectionAndSpinCount = nullptr;
		inline APIHandler InitializeCriticalSectionEx = nullptr;
		inline APIHandler RtlInitializeCriticalSectionEx = nullptr;
		inline APIHandler RtlInitializeCriticalSectionAndSpinCount = nullptr;
		inline APIHandler RtlEnterCriticalSection = nullptr;
		inline APIHandler RtlLeaveCriticalSection = nullptr;
		inline APIHandler RtlDeleteCriticalSection = nullptr;

		/* CRT */
		inline APIHandler InitializeSListHead = nullptr;

		/* FLS & TLS */
		inline APIHandler FlsAlloc = nullptr;
		inline APIHandler FlsGetValue = nullptr;
		inline APIHandler FlsSetValue = nullptr;
		inline APIHandler FlsFree = nullptr;

		inline APIHandler TlsAlloc = nullptr;
		inline APIHandler TlsGetValue = nullptr;
		inline APIHandler TlsSetValue = nullptr;
		inline APIHandler TlsFree = nullptr;

		/* Memory related */
		inline APIHandler VirtualProtect = nullptr;
		inline APIHandler GetProcessHeap = nullptr;

		inline APIHandler GetLastError = nullptr;

	};
}

extern InstructionExceptionInfo g_instruction_exception_table [ X86_INS_ENDING ];

struct StateSnapshot {
	std::array<uint64_t, KGPR_COUNT> registers;
	std::unordered_map<uint64_t, uint64_t> memory; // Stack and memory
	int64_t rsp_value;
	std::unordered_set<x86_reg> modified_regs; // Normalized
	std::unordered_set<uint64_t> modified_mem;
};


extern template void EmulationContext::update_mxcsr_arithmetic<float> ( float, float, float, InstructionEffect& );
extern template void EmulationContext::update_mxcsr_arithmetic<double> ( double, double, double, InstructionEffect& );
extern template void EmulationContext::update_flags_for_compare<float> ( float, float, bool, InstructionEffect& );
extern template void EmulationContext::update_flags_for_compare<double> ( double, double, bool, InstructionEffect& );
extern template void EmulationContext::update_mxcsr_conversion_float_to_int<float, int32_t> ( float, int32_t, bool, InstructionEffect& );
extern template void EmulationContext::update_mxcsr_conversion_float_to_int<float, int64_t> ( float, int64_t, bool, InstructionEffect& );
extern template void EmulationContext::update_mxcsr_conversion_float_to_int<double, int32_t> ( double, int32_t, bool, InstructionEffect& );
extern template void EmulationContext::update_mxcsr_conversion_float_to_int<double, int64_t> ( double, int64_t, bool, InstructionEffect& );
extern template void EmulationContext::update_mxcsr_conversion_int_to_float<int32_t, float> ( int32_t, float, InstructionEffect& );
extern template void EmulationContext::update_mxcsr_conversion_int_to_float<int64_t, float> ( int64_t, float, InstructionEffect& );
extern template void EmulationContext::update_mxcsr_conversion_int_to_float<int32_t, double> ( int32_t, double, InstructionEffect& );
extern template void EmulationContext::update_mxcsr_conversion_int_to_float<int64_t, double> ( int64_t, double, InstructionEffect& );
extern template const uint8_t& EmulationContext::get_reg<uint8_t> ( x86_reg ) const;
extern template const uint16_t& EmulationContext::get_reg<uint16_t> ( x86_reg ) const;
extern template const uint32_t& EmulationContext::get_reg<uint32_t> ( x86_reg ) const;
extern template const uint64_t& EmulationContext::get_reg<uint64_t> ( x86_reg ) const;
extern template uint8_t& EmulationContext::get_reg_mut<uint8_t> ( x86_reg );
extern template uint16_t& EmulationContext::get_reg_mut<uint16_t> ( x86_reg );
extern template uint32_t& EmulationContext::get_reg_mut<uint32_t> ( x86_reg );
extern template uint64_t& EmulationContext::get_reg_mut<uint64_t> ( x86_reg );

GuestExceptionInfo check_instruction_exceptions (
		EmulationContext& state,
		class capstone::Instruction& instr,
		const PreCheckInfo& check_info
);

// --- Forward declarations for post-checkers ---
GuestExceptionInfo check_post_execution_arithmetic (
		EmulationContext& state,
		const InstructionExceptionInfo& baseInfo,
		uint64_t ip,
		uint8_t op_size // Pass operand size used by the instruction
);

GuestExceptionInfo check_post_execution_fpu_simd (
		EmulationContext& state,
		const InstructionExceptionInfo& baseInfo, // Needed to know if instr could raise FP exceptions
		uint64_t ip
);

void populate_pre_check_info (
		PreCheckInfo& check_info,           // Out parameter
		EmulationContext& state,            // Current state
		capstone::Instruction& instr, // Decoded instruction
		const InstructionExceptionInfo& baseInfo // Static info from table
);

void setup_guest_exception_dispatch ( EmulationContext& state, const GuestExceptionInfo& ex_info );

inline const std::unordered_map<x86_insn, Handler*> instruction_handlers = {
	// Data movement
	{X86_INS_MOV, &handlers::mov},
	{X86_INS_MOVABS, &handlers::movabs},
	{X86_INS_MOVAPS, &handlers::movaps},
	{X86_INS_MOVUPS, &handlers::movups},
	{X86_INS_MOVDQU, &handlers::movdqu},
	{X86_INS_MOVQ, &handlers::movq},
	{X86_INS_MOVZX, &handlers::movzx},
	{X86_INS_MOVSX, &handlers::movsx},
	{X86_INS_PUSH, &handlers::push},
	{X86_INS_PUSHFQ, &handlers::pushfq},
	{X86_INS_POPFQ, &handlers::popfq},
	{X86_INS_POP, &handlers::pop},
	{X86_INS_LEA, &handlers::lea},
	{X86_INS_SAHF, &handlers::sahf},
	{X86_INS_LAHF, &handlers::lahf},
	{X86_INS_MOVSXD, &handlers::movsxd},
	{X86_INS_XCHG, &handlers::xchg},
	{X86_INS_STOSB, &handlers::stos},
	{X86_INS_STOSW, &handlers::stos},
	{X86_INS_STOSD, &handlers::stos},
	{X86_INS_STOSQ, &handlers::stos},
	{X86_INS_PUNPCKLQDQ , &handlers::punpcklqdq},
	{X86_INS_PREFETCHW , &handlers::prefetchw},
	{X86_INS_PSRLDQ , &handlers::psrldq},
	// Arithmetic
	{X86_INS_ADD, &handlers::add},
	{X86_INS_XADD, &handlers::xadd},
	{X86_INS_SUB, &handlers::sub},
	{X86_INS_INC, &handlers::inc},
	{X86_INS_DEC, &handlers::dec},
	{X86_INS_MUL, &handlers::mul},
	{X86_INS_IMUL, &handlers::imul},
	{X86_INS_DIV, &handlers::div},
	{X86_INS_IDIV, &handlers::idiv},
	{X86_INS_CDQ, &handlers::cdq},
	{X86_INS_CDQE, &handlers::cdqe},
	{X86_INS_ADC, &handlers::adc},
	{X86_INS_NEG, &handlers::neg},
	{X86_INS_SBB, &handlers::sbb},

	// Logical and shifts
	{X86_INS_AND, &handlers::and_},
	{X86_INS_OR, &handlers::or_},
	{X86_INS_XOR, &handlers::xor_},
	{X86_INS_NOT, &handlers::not_},
	{X86_INS_SHL, &handlers::shl},
	{X86_INS_SHLD, &handlers::shld},
	{X86_INS_SHR, &handlers::shr},
	{X86_INS_SHRD, &handlers::shrd},
	{X86_INS_SAR, &handlers::sar},
	{X86_INS_SAL, &handlers::sal},
	{X86_INS_MOVLHPS , &handlers::movlhps},

	// Conditional moves
	{X86_INS_CMOVO, &handlers::cmovo},
	{X86_INS_CMOVGE, &handlers::cmovnl},
	{X86_INS_CMOVBE, &handlers::cmovbe},
	{X86_INS_CMOVE, &handlers::cmovz},
	{X86_INS_CMOVLE, &handlers::cmovle},
	{X86_INS_CMOVL, &handlers::cmovl},
	{X86_INS_CMOVNP, &handlers::cmovnp},
	{X86_INS_CMOVNS, &handlers::cmovns},
	{X86_INS_CMOVP, &handlers::cmovp},
	{X86_INS_CMOVAE, &handlers::cmovnb},
	{X86_INS_CMOVNO, &handlers::cmovno},
	{X86_INS_CMOVS, &handlers::cmovs},
	{X86_INS_CMOVNE, &handlers::cmovnz},
	{X86_INS_CMOVA, &handlers::cmovnbe},
	{X86_INS_CMOVG, &handlers::cmovnle},
	{X86_INS_CMOVB, &handlers::cmovb},
	{X86_INS_RDRAND, &handlers::rdrand},

	// Comparisons and jumps
	{X86_INS_CMP, &handlers::cmp},
	{X86_INS_CMPXCHG, &handlers::cmpxchg},
	{X86_INS_CMPXCHG16B, &handlers::cmpxchg16b},
	{X86_INS_TEST, &handlers::test},
	{X86_INS_CALL, &handlers::call},
	{X86_INS_RET, &handlers::ret},
	{X86_INS_JMP, &handlers::jmp},
	{X86_INS_JE, &handlers::je},
	{X86_INS_JNE, &handlers::jne},
	{X86_INS_JA, &handlers::jnbe},
	{X86_INS_JG, &handlers::jg},
	{X86_INS_JL, &handlers::jl},
	{X86_INS_JAE, &handlers::jnb},
	{X86_INS_JB, &handlers::jb},
	{X86_INS_JNS, &handlers::jns},
	{X86_INS_JGE, &handlers::jnl},
	{X86_INS_JO, &handlers::jo},
	{X86_INS_JNO, &handlers::jno},
	{X86_INS_JS, &handlers::js},
	{X86_INS_JBE, &handlers::jbe},
	{X86_INS_JLE, &handlers::jle},
	{X86_INS_JP, &handlers::jp},
	{X86_INS_JNP, &handlers::jnp},
	{X86_INS_JCXZ, &handlers::jcxz},
	{X86_INS_JECXZ, &handlers::jecxz},
	{X86_INS_JRCXZ, &handlers::jrcxz},

	// Stack and control
	{X86_INS_ENTER, &handlers::enter},
	{X86_INS_LEAVE, &handlers::leave},
	{X86_INS_NOP, &handlers::nop},

	// Bit manipulation and misc
	{X86_INS_BZHI, &handlers::bzhi},
	{X86_INS_ANDN, &handlers::andn},
	{X86_INS_BEXTR, &handlers::bextr},
	{X86_INS_ROR, &handlers::ror},
	{X86_INS_ROL, &handlers::rol},
	{X86_INS_POPCNT, &handlers::popcnt},
	{X86_INS_TZCNT, &handlers::tzcnt },
	{X86_INS_BSWAP, &handlers::bswap},
	{X86_INS_BSR, &handlers::bsr },
	{X86_INS_SETB, &handlers::setb},
	{X86_INS_SETBE, &handlers::setbe},
	{X86_INS_SETNP, &handlers::setnp},
	{X86_INS_SETGE, &handlers::setnl},
	{X86_INS_SETS, &handlers::sets},
	{X86_INS_SETO, &handlers::seto},
	{X86_INS_SETE, &handlers::setz},
	{X86_INS_SETAE, &handlers::setnb},
	{X86_INS_SETNO, &handlers::setno},
	{X86_INS_RCR, &handlers::rcr},
	{X86_INS_RCL, &handlers::rcl},
	{X86_INS_BT, &handlers::bt},
	{X86_INS_SETP, &handlers::setp},
	{X86_INS_SETLE, &handlers::setle},
	{X86_INS_SETG, &handlers::setnle},
	{X86_INS_SETNS, &handlers::setns},
	{X86_INS_SETL, &handlers::setl},
	{X86_INS_SETA, &handlers::setnbe},
	{X86_INS_SETNE, &handlers::setnz},
	{X86_INS_CLI, &handlers::cli},
	{X86_INS_BTR, &handlers::btr},
	{X86_INS_BTS, &handlers::bts},
	{X86_INS_CBW, &handlers::cbw},
	{X86_INS_CQO, &handlers::cqo},
	{X86_INS_BTC, &handlers::btc},
	{X86_INS_CWD, &handlers::cwd},
	{X86_INS_CWDE, &handlers::cwde},
	{X86_INS_CLD, &handlers::cld},
	{X86_INS_CLC, &handlers::clc},
	{X86_INS_CMC, &handlers::cmc},
	{X86_INS_STC, &handlers::stc},
	{ X86_INS_BSF, &handlers::bsf },

	// SIMD

	{ X86_INS_MOVSB, &handlers::movsb },
	{ X86_INS_MOVSW, &handlers::movsw },
	{ X86_INS_MOVSQ, &handlers::movsq },
	{ X86_INS_MOVSD, &handlers::movsd },

	{X86_INS_MOVSS, &handlers::movss},
	{X86_INS_ADDSS, &handlers::addss},
	{X86_INS_CMPSS, &handlers::cmpss},
	{X86_INS_MULSS, &handlers::mulss},
	{X86_INS_DIVSS, &handlers::divss},
	{X86_INS_SQRTSS, &handlers::sqrtss},
	{X86_INS_SQRTSD, &handlers::sqrtsd},
	{X86_INS_CVTSS2SI, &handlers::cvtss2si},
	{X86_INS_SUBSS, &handlers::subss},
	{X86_INS_MINSS, &handlers::minss},
	{X86_INS_MAXSS, &handlers::maxss},
	{X86_INS_COMISS, &handlers::comiss},
	{X86_INS_ROUNDSS, &handlers::roundss},
	{X86_INS_RCPSS, &handlers::rcpss},
	{X86_INS_RSQRTSS, &handlers::rsqrtss},
	{X86_INS_UCOMISS, &handlers::ucomiss},
	{X86_INS_CVTSI2SS, &handlers::cvtsi2ss},
	{X86_INS_CVTTSS2SI, &handlers::cvttss2si},
	{X86_INS_CVTSS2SD, &handlers::cvtss2sd},
	{X86_INS_CVTSD2SS, &handlers::cvtsd2ss},
	{X86_INS_ANDPS, &handlers::andps},
	{X86_INS_ORPS, &handlers::orps},
	{X86_INS_XORPS, &handlers::xorps},
	{X86_INS_MOVHLPS, &handlers::movhlps},
	{X86_INS_UNPCKLPS, &handlers::unpcklps},
	{X86_INS_CVTSI2SD, &handlers::cvtsi2sd},
	{X86_INS_MULSD, &handlers::mulsd},
	{X86_INS_COMISD, &handlers::comisd},
	{X86_INS_FLD, &handlers::fld },
	{X86_INS_FPREM, &handlers::fprem },
	{X86_INS_FSTP, &handlers::fstp },
	{X86_INS_FFREE, &handlers::ffree },
	{X86_INS_FINCSTP, &handlers::fincstp },
	{X86_INS_FMUL, &handlers::fmul },
	{X86_INS_FMULP, &handlers::fmulp },

	// AVX
	{X86_INS_VPXOR, &handlers::vpxor },
	{X86_INS_VPCMPEQW, &handlers::vpcmpeqw },
	{X86_INS_VPMOVMSKB, &handlers::vpmovmskb },
	{X86_INS_VZEROUPPER, &handlers::vzeroupper },
	{X86_INS_VINSERTF128, &handlers::vinsertf128 },
	{X86_INS_VMOVUPS, &handlers::vmovups },
	{X86_INS_VMOVAPS, &handlers::vmovaps },
	{X86_INS_VMOVDQU, &handlers::vmovdqu },

	// System & Others
	{X86_INS_RDTSC, &handlers::rdtsc},
	{X86_INS_CPUID, &handlers::cpuid},
	{X86_INS_XGETBV, &handlers::xgetbv},
	{X86_INS_SYSCALL, &handlers::syscall},
	{X86_INS_BOUND, &handlers::bound},
	{X86_INS_FXSAVE, &handlers::fxsave },
	{X86_INS_FXRSTOR, &handlers::fxrstor },
	{X86_INS_INT, &handlers::int_},
	{X86_INS_INT1, &handlers::int1},
	{X86_INS_INT3, &handlers::int3},
	{X86_INS_HLT, &handlers::hlt},
	{X86_INS_STMXCSR, &handlers::stmxcsr},
	{X86_INS_LDMXCSR, &handlers::ldmxcsr},
	{ X86_INS_FNSTCW, &handlers::fnstcw },

	{ X86_INS_IN, &handlers::io_in },
	{ X86_INS_OUT, &handlers::io_out },
	{ X86_INS_OUTSB, &handlers::outx },
	{ X86_INS_OUTSW, &handlers::outx },
	{ X86_INS_OUTSD, &handlers::outx },

};

class FlagLogger {
public:
	FlagLogger ( EmulationContext* emu, InstructionEffect& effect_ref ) : ctx ( emu ), effect ( effect_ref ) {
		initial_flags = emu->cpu->cpu_flags.flags.value;
	}

	~FlagLogger ( ) {
		ctx->log_rflags_changes ( initial_flags, ctx->cpu->cpu_flags.flags.value, effect );
	}

private:
	EmulationContext* ctx;
	InstructionEffect& effect;
	uint64_t initial_flags;
};