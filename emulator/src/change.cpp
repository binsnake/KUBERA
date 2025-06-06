#include "pch.hpp"

InstructionEffect EmulationContext::log_effect ( capstone::Instruction& instr ) {
	return InstructionEffect { instr.to_string ( ), {} };
}

void EmulationContext::log_reg_change ( InstructionEffect& effect, x86_reg reg, uint64_t old_val, uint64_t new_val, const char* op ) {
	if constexpr ( STATE_TRACKING ) {
		if ( !options.enable_logging ) {
			return;
		}
		effect.push_to_changes ( std::format ( "{} {} {:#x} (pv: {:#x})",
														 cs_reg_name ( decoder.back ( )->get_handle ( ), reg ), op, new_val, old_val ) );
	}
}

void EmulationContext::log_reg_change ( InstructionEffect& effect, x86_reg reg, int128_t old_val, int128_t new_val, const char* op ) {
	if constexpr ( STATE_TRACKING ) {
		if ( !options.enable_logging ) {
			return;
		}
		effect.push_to_changes ( std::format ( "{} {} {} (pv: {})",
														 cs_reg_name ( decoder.back ( )->get_handle ( ), reg ), op, new_val.convert_to<double> ( ), old_val.convert_to<double> ( ) ) );
	}
}

void EmulationContext::log_flag_change ( InstructionEffect& effect, const char* flag, uint64_t old_val, uint64_t new_val ) {
	if constexpr ( STATE_TRACKING ) {
		if ( !options.enable_logging ) {
			return;
		}
		effect.push_to_changes ( std::format ( "flags.{}={} (pv: {})", flag, new_val, old_val ) );
	}
}

void EmulationContext::log_rflags_changes ( uint64_t old_rflags, uint64_t new_rflags, InstructionEffect& effect ) noexcept {
	if constexpr ( STATE_TRACKING ) {
		if ( !options.enable_logging ) {
			return;
		}

		uint64_t changed_bits = old_rflags ^ new_rflags;

		if ( changed_bits == 0 ) {
			return;
		}

		static constexpr struct {
			const char* name;
			uint8_t bit_pos;
			uint8_t bit_width;
		} flag_info [ ] = {
				{"CF", 0, 1},
				{"PF", 2, 1},
				{"AF", 4, 1},
				{"ZF", 6, 1},
				{"SF", 7, 1},
				{"TF", 8, 1},
				{"IF", 9, 1},
				{"DF", 10, 1},
				{"OF", 11, 1},
				{"IOPL", 12, 2},
				{"NT", 14, 1},
				{"RF", 16, 1},
				{"VM", 17, 1},
				{"AC", 18, 1},
				{"VIF", 19, 1},
				{"VIP", 20, 1},
				{"ID", 21, 1}
		};

		for ( const auto& flag : flag_info ) {
			uint64_t mask = ( ( 1ULL << flag.bit_width ) - 1 ) << flag.bit_pos;

			if ( changed_bits & mask ) {
				uint64_t old_value = ( old_rflags >> flag.bit_pos ) & ( ( 1ULL << flag.bit_width ) - 1 );
				uint64_t new_value = ( new_rflags >> flag.bit_pos ) & ( ( 1ULL << flag.bit_width ) - 1 );
				log_flag_change ( effect, flag.name, old_value, new_value );
			}
		}
	}
}

void EmulationContext::log_stack_change ( InstructionEffect& effect, int64_t addr, uint64_t old_val, uint64_t new_val, uint8_t size ) {
	if constexpr ( STATE_TRACKING ) {
		if ( !options.enable_logging ) {
			return;
		}
		// Format the log message including the size of the write
		effect.push_to_changes ( std::format ( "[0x{:x}] ({}-byte) = {:#x} (was {:#x})", addr, size, new_val, old_val ) );
	}
}

void InstructionEffect::push_to_changes ( const EmulationContext& ctx, const std::string& data ) {
	if constexpr ( STATE_TRACKING ) { // for better optimization
		if ( ctx.options.enable_logging ) {
			changes.emplace_back ( data );
		}
	}
}
void InstructionEffect::push_to_changes ( const EmulationContext* ctx, const std::string& data ) {
	if constexpr ( STATE_TRACKING ) { // for better optimization
		if ( ctx->options.enable_logging ) {
			changes.emplace_back ( data );
		}
	}
}

void InstructionEffect::push_to_changes ( const std::string& data ) {
	if constexpr ( STATE_TRACKING ) { // for better optimization
		changes.emplace_back ( data );
	}
}