#include "pch.hpp"

InstructionEffect EmulationContext::log_effect ( capstone::Instruction& instr ) {
	return InstructionEffect { instr.to_string ( ), {} };
}

void EmulationContext::log_reg_change ( InstructionEffect& effect, x86_reg reg, uint64_t old_val, uint64_t new_val, const char* op ) {
	if ( !options.enable_logging ) {
		return;
	}
	effect.push_to_changes ( std::format ( "{} {} {:#x} (pv: {:#x})",
													 cs_reg_name ( decoder.back()->get_handle ( ), reg ), op, new_val, old_val ) );
}

void EmulationContext::log_reg_change ( InstructionEffect& effect, x86_reg reg, int128_t old_val, int128_t new_val, const char* op ) {
	if ( !options.enable_logging ) {
		return;
	}
	effect.push_to_changes ( std::format ( "{} {} {} (pv: {})",
													 cs_reg_name ( decoder.back()->get_handle ( ), reg ), op, new_val.convert_to<double> ( ), old_val.convert_to<double> ( ) ) );
}

void EmulationContext::log_flag_change ( InstructionEffect& effect, const char* flag, uint64_t old_val, uint64_t new_val ) {
	if ( !options.enable_logging ) {
		return;
	}
	effect.push_to_changes ( std::format ( "flags.{}={} (pv: {})", flag, new_val, old_val ) );
}

void EmulationContext::log_stack_change ( InstructionEffect& effect, int64_t addr, uint64_t old_val, uint64_t new_val, uint8_t size ) {
	if ( !options.enable_logging ) {
		return;
	}
	// Format the log message including the size of the write
	effect.push_to_changes ( std::format ( "[0x{:x}] ({}-byte) = {:#x} (was {:#x})", addr, size, new_val, old_val ) );
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