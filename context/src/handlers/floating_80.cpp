#include <context/emulator.hpp>
#include <bit>
#include "helpers.hpp"

using namespace kubera;

// Helper function to check FPU exceptions and set status flags
void check_fpu_exception ( x86::FPUStatusWord& fsw, const x86::FPUControlWord& fcw, uint16_t determined_fsw_flags ) {
	fsw.value |= determined_fsw_flags; // Set determined flags in FSW

	// Check for unmasked exceptions
	bool unmasked_occurred = false;
	if ( ( determined_fsw_flags & x86::FSW_IE ) && !fcw.IM ) unmasked_occurred = true;
	if ( ( determined_fsw_flags & x86::FSW_DE ) && !fcw.DM ) unmasked_occurred = true;
	if ( ( determined_fsw_flags & x86::FSW_ZE ) && !fcw.ZM ) unmasked_occurred = true;
	if ( ( determined_fsw_flags & x86::FSW_OE ) && !fcw.OM ) unmasked_occurred = true;
	if ( ( determined_fsw_flags & x86::FSW_UE ) && !fcw.UM ) unmasked_occurred = true;
	if ( ( determined_fsw_flags & x86::FSW_PE ) && !fcw.PM ) unmasked_occurred = true;
	if ( determined_fsw_flags & x86::FSW_SF ) unmasked_occurred = true; // Stack fault is unmaskable

	if ( unmasked_occurred ) {
		fsw.ES = 1; // Set Error Summary
		// !TODO(exception)
	}
}

/// FLD - Load Floating-Point Value
/// Loads a floating-point value from memory (32-bit, 64-bit, or 80-bit) or an FPU register (ST(i)) onto the FPU stack, modifying C1 (set on stack overflow, cleared otherwise), TOP (decremented), and possibly IE, SF, or DE.
void handlers::fld ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_size ( );
	auto& fpu = context.get_fpu ( );
	const int next_top = ( fpu.fpu_top - 1 + 8 ) % 8;
	const int st7_phys_idx = ( next_top + 7 ) % 8;
	uint16_t fsw_flags = 0;

	if ( fpu.get_fpu_tag ( st7_phys_idx ) != x86::FPU_TAG_EMPTY ) {
		fsw_flags |= ( x86::FSW_IE | x86::FSW_SF | x86::FSW_C1 );
		check_fpu_exception ( fpu.fpu_status_word, fpu.fpu_control_word, fsw_flags );
		return;
	}

	float80_t value;
	if ( instr.op0_kind ( ) == OpKindSimple::Memory ) {
		const uint64_t addr = helpers::calculate_mem_addr ( instr, context );
		if ( op_size == 4 ) {
			value = helpers::get_operand_value<float> ( instr, 0u, context );
		}
		else if ( op_size == 8 ) {
			value = helpers::get_operand_value<double> ( instr, 0u, context );
		}
		else if ( op_size == 10 ) {
			value = context.read_type_float80_t ( addr );
		}
		else {
			// !TODO(exception)
			return;
		}
		if ( fpu.classify_fpu_operand ( value ) == x86::FPU_TAG_SPECIAL ) {
			if ( boost::multiprecision::fpclassify ( value ) == FP_SUBNORMAL ) {
				fsw_flags |= x86::FSW_DE;
			}
			else if ( boost::multiprecision::isnan ( value ) ) {
				fsw_flags |= x86::FSW_IE;
			}
		}
	}
	else if ( instr.op0_kind ( ) == OpKindSimple::Register &&
					instr.op0_reg ( ) >= Register::ST0 && instr.op0_reg ( ) <= Register::ST7 ) {
		const int src_sti = static_cast< int >( instr.op0_reg ( ) ) - static_cast< int >( Register::ST0 );
		const int src_phys_idx = fpu.get_fpu_phys_idx ( src_sti );
		if ( fpu.get_fpu_tag ( src_phys_idx ) == x86::FPU_TAG_EMPTY ) {
			fsw_flags |= ( x86::FSW_IE | x86::FSW_SF );
			check_fpu_exception ( fpu.fpu_status_word, fpu.fpu_control_word, fsw_flags );
			return;
		}
		value = fpu.fpu_stack [ src_phys_idx ];
	}
	else {
		// !TODO(exception)
		return;
	}

	fpu.fpu_top = next_top;
	fpu.fpu_stack [ fpu.fpu_top ] = value;
	fpu.fpu_status_word.C1 = 0;
	fpu.update_fsw_top ( );
	fpu.set_fpu_tag ( fpu.fpu_top, fpu.classify_fpu_operand ( value ) );
	check_fpu_exception ( fpu.fpu_status_word, fpu.fpu_control_word, fsw_flags );
}

/// FPREM - Partial Remainder
/// Computes the partial remainder of ST(0) divided by ST(1), storing the result in ST(0), modifying C2 (set if reduction incomplete), C0, C1, C3 (cleared), IE, DE, UE, and TOP indirectly.
void handlers::fprem ( const iced::Instruction& instr, KUBERA& context ) {
	auto& fpu = context.get_fpu ( );
	const int st0_phys_idx = fpu.fpu_top;
	const int st1_phys_idx = ( fpu.fpu_top + 1 ) % 8;
	uint16_t fsw_flags = 0;

	if ( fpu.get_fpu_tag ( st0_phys_idx ) == x86::FPU_TAG_EMPTY ||
			fpu.get_fpu_tag ( st1_phys_idx ) == x86::FPU_TAG_EMPTY ) {
		fsw_flags |= ( x86::FSW_IE | x86::FSW_SF | x86::FSW_C2 );
		check_fpu_exception ( fpu.fpu_status_word, fpu.fpu_control_word, fsw_flags );
		return;
	}

	const float80_t st0_val = fpu.fpu_stack [ st0_phys_idx ];
	const float80_t st1_val = fpu.fpu_stack [ st1_phys_idx ];

	if ( boost::multiprecision::isnan ( st0_val ) || boost::multiprecision::isnan ( st1_val ) ||
			boost::multiprecision::isinf ( st0_val ) || boost::multiprecision::isinf ( st1_val ) ||
			st1_val == 0 ) {
		fsw_flags |= x86::FSW_IE;
		fpu.fpu_status_word.C2 = 1;
		check_fpu_exception ( fpu.fpu_status_word, fpu.fpu_control_word, fsw_flags );
		return;
	}

	if ( boost::multiprecision::fpclassify ( st0_val ) == FP_SUBNORMAL ||
			boost::multiprecision::fpclassify ( st1_val ) == FP_SUBNORMAL ) {
		fsw_flags |= x86::FSW_DE;
	}

	float80_t result = boost::multiprecision::remainder ( st0_val, st1_val );
	if ( result == 0 && st0_val != 0 ) {
		result = st0_val;
	}

	if ( boost::multiprecision::fpclassify ( result ) == FP_SUBNORMAL && result != 0 ) {
		fsw_flags |= ( x86::FSW_UE | x86::FSW_DE );
	}

	const int exp0 = st0_val.backend ( ).exponent ( );
	const int exp1 = st1_val.backend ( ).exponent ( );
	if ( exp0 - exp1 >= 64 ) {
		fpu.fpu_status_word.C2 = 1;
		fpu.fpu_status_word.C0 = 0;
		fpu.fpu_status_word.C1 = 0;
		fpu.fpu_status_word.C3 = 0;
	}
	else {
		fpu.fpu_status_word.C2 = 0;
		fpu.fpu_status_word.C0 = 0;
		fpu.fpu_status_word.C1 = 0;
		fpu.fpu_status_word.C3 = 0;
	}

	fpu.fpu_stack [ st0_phys_idx ] = result;
	fpu.set_fpu_tag ( st0_phys_idx, fpu.classify_fpu_operand ( result ) );
	check_fpu_exception ( fpu.fpu_status_word, fpu.fpu_control_word, fsw_flags );
}

/// FSTP - Store Floating-Point Value and Pop
/// Stores ST(0) to memory (32-bit, 64-bit, or 80-bit) or an FPU register (ST(i)) and pops the FPU stack, modifying C1 (set on underflow/overflow, cleared otherwise), IE, DE, UE, OE, PE, and TOP (incremented).
void handlers::fstp ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_size ( );
	auto& fpu = context.get_fpu ( );
	const int st0_phys_idx = fpu.fpu_top;
	uint16_t fsw_flags = 0;

	if ( fpu.get_fpu_tag ( st0_phys_idx ) == x86::FPU_TAG_EMPTY ) {
		fsw_flags |= ( x86::FSW_IE | x86::FSW_SF | x86::FSW_C1 );
		check_fpu_exception ( fpu.fpu_status_word, fpu.fpu_control_word, fsw_flags );
		return;
	}

	const float80_t value = fpu.fpu_stack [ st0_phys_idx ];
	if ( boost::multiprecision::isnan ( value ) ) {
		fsw_flags |= x86::FSW_IE;
	}
	if ( boost::multiprecision::fpclassify ( value ) == FP_SUBNORMAL ) {
		fsw_flags |= x86::FSW_DE;
	}

	if ( instr.op0_kind ( ) == OpKindSimple::Memory ) {
		const uint64_t addr = helpers::get_operand_value<uint64_t> ( instr, 0u, context );
		if ( op_size == 4 ) {
			const float f_val = value.convert_to<float> ( );
			const uint32_t f_bits = std::bit_cast< uint32_t >( f_val );
			helpers::set_operand_value<uint32_t> ( instr, 0u, f_bits, context );
			const float80_t check_back = f_val;
			if ( f_val != 0 && value != 0 && check_back == 0 ) fsw_flags |= x86::FSW_UE;
			if ( !boost::multiprecision::isinf ( check_back ) && boost::multiprecision::isinf ( value ) ) fsw_flags |= x86::FSW_OE;
			if ( check_back != value ) fsw_flags |= x86::FSW_PE;
		}
		else if ( op_size == 8 ) {
			const double d_val = value.convert_to<double> ( );
			const uint64_t d_bits = std::bit_cast< uint64_t >( d_val );
			helpers::set_operand_value<uint64_t> ( instr, 0u, d_bits, context );
			const float80_t check_back = d_val;
			if ( d_val != 0 && value != 0 && check_back == 0 ) fsw_flags |= x86::FSW_UE;
			if ( !boost::multiprecision::isinf ( check_back ) && boost::multiprecision::isinf ( value ) ) fsw_flags |= x86::FSW_OE;
			if ( check_back != value ) fsw_flags |= x86::FSW_PE;
		}
		else if ( op_size == 10 ) {
			context.write_type ( addr, value );
		}
		else {
			// !TODO(exception)
			return;
		}
	}
	else if ( instr.op0_kind ( ) == OpKindSimple::Register &&
					instr.op0_reg ( ) >= Register::ST0 && instr.op0_reg ( ) <= Register::ST7 ) {
		const int dst_sti = static_cast< int >( instr.op0_reg ( ) ) - static_cast< int >( Register::ST0 );
		const int dst_phys_idx = fpu.get_fpu_phys_idx ( dst_sti );
		fpu.fpu_stack [ dst_phys_idx ] = value;
		fpu.set_fpu_tag ( dst_phys_idx, fpu.classify_fpu_operand ( value ) );
	}
	else {
		// !TODO(exception)
		return;
	}

	fpu.fpu_status_word.C1 = ( fsw_flags & ( x86::FSW_UE | x86::FSW_OE ) ) ? 1 : 0;
	fpu.set_fpu_tag ( st0_phys_idx, x86::FPU_TAG_EMPTY );
	fpu.fpu_top = ( fpu.fpu_top + 1 ) % 8;
	fpu.update_fsw_top ( );
	check_fpu_exception ( fpu.fpu_status_word, fpu.fpu_control_word, fsw_flags );
}

/// FFREE - Free FPU Register
/// Marks the specified FPU register (ST(i)) as empty, without modifying FPU status flags directly, but affecting TOP indirectly via tag updates.
void handlers::ffree ( const iced::Instruction& instr, KUBERA& context ) {
	if ( instr.op0_kind ( ) == OpKindSimple::Register &&
			instr.op0_reg ( ) >= Register::ST0 && instr.op0_reg ( ) <= Register::ST7 ) {
		const int sti = static_cast< int >( instr.op0_reg ( ) ) - static_cast< int >( Register::ST0 );
		const int phys_idx = context.get_fpu ( ).get_fpu_phys_idx ( sti );
		context.get_fpu ( ).set_fpu_tag ( phys_idx, x86::FPU_TAG_EMPTY );
	}
	else {
		// !TODO(exception)
	}
}

/// FINCSTP - Increment FPU Stack Pointer
/// Increments the FPU stack top pointer, clearing C1 and modifying TOP.
void handlers::fincstp ( const iced::Instruction& instr, KUBERA& context ) {
	auto& fpu = context.get_fpu ( );
	fpu.fpu_top = ( fpu.fpu_top + 1 ) % 8;
	fpu.fpu_status_word.C1 = 0;
	fpu.update_fsw_top ( );
}

/// FMUL - Floating-Point Multiply
/// Multiplies ST(0) or ST(i) with another operand (ST(i) or memory), storing the result in ST(0) or ST(i), modifying IE, DE, OE, UE, PE, and C1 (cleared). FMULP pops the stack, incrementing TOP.
void handlers::fmul ( const iced::Instruction& instr, KUBERA& context ) {
	const bool pop_stack = ( instr.mnemonic ( ) == Mnemonic::Fmulp );
	const size_t op_count = instr.op_count ( );
	auto& fpu = context.get_fpu ( );
	const int st0_phys_idx = fpu.fpu_top;
	uint16_t fsw_flags = 0;
	float80_t operand1, operand2, result;
	int dst_phys_idx = st0_phys_idx;
	int dst_sti = 0;
	const int sti = static_cast< int >( instr.op0_reg ( ) ) - static_cast< int >( Register::ST0 );
	if ( op_count == 0 ) {
		const int st1_phys_idx = fpu.get_fpu_phys_idx ( 1 );
		dst_phys_idx = st1_phys_idx;
		dst_sti = 1;
		if ( fpu.get_fpu_tag ( st0_phys_idx ) == x86::FPU_TAG_EMPTY ||
				fpu.get_fpu_tag ( st1_phys_idx ) == x86::FPU_TAG_EMPTY ) {
			fsw_flags |= ( x86::FSW_IE | x86::FSW_SF );
			check_fpu_exception ( fpu.fpu_status_word, fpu.fpu_control_word, fsw_flags );
			return;
		}
		operand1 = fpu.fpu_stack [ st1_phys_idx ];
		operand2 = fpu.fpu_stack [ st0_phys_idx ];
	}
	else if ( op_count == 1 ) {
		if ( fpu.get_fpu_tag ( st0_phys_idx ) == x86::FPU_TAG_EMPTY ) {
			fsw_flags |= ( x86::FSW_IE | x86::FSW_SF );
			check_fpu_exception ( fpu.fpu_status_word, fpu.fpu_control_word, fsw_flags );
			return;
		}
		operand1 = fpu.fpu_stack [ st0_phys_idx ];
		if ( instr.op0_kind ( ) == OpKindSimple::Memory ) {
			const size_t op_size = instr.op0_size ( );
			if ( op_size == 4 ) {
				operand2 = helpers::get_operand_value<float> ( instr, 0u, context );
			}
			else if ( op_size == 8 ) {
				operand2 = helpers::get_operand_value<double> ( instr, 0u, context );
			}
			else {
				// !TODO(exception)
				return;
			}
		}
		else if ( instr.op0_kind ( ) == OpKindSimple::Register &&
						instr.op0_reg ( ) >= Register::ST0 && instr.op0_reg ( ) <= Register::ST7 ) {
			const int sti_phys_idx = fpu.get_fpu_phys_idx ( sti );
			if ( fpu.get_fpu_tag ( sti_phys_idx ) == x86::FPU_TAG_EMPTY ) {
				fsw_flags |= ( x86::FSW_IE | x86::FSW_SF );
				check_fpu_exception ( fpu.fpu_status_word, fpu.fpu_control_word, fsw_flags );
				return;
			}
			operand2 = fpu.fpu_stack [ sti_phys_idx ];
		}
		else {
			// !TODO(exception)
			return;
		}
	}
	else if ( op_count == 2 ) {
		if ( instr.op0_kind ( ) == OpKindSimple::Register &&
				instr.op0_reg ( ) >= Register::ST0 && instr.op0_reg ( ) <= Register::ST7 &&
				instr.op1_kind ( ) == OpKindSimple::Register && instr.op1_reg ( ) == Register::ST0 ) {
			dst_phys_idx = fpu.get_fpu_phys_idx ( sti );
			dst_sti = sti;
			if ( fpu.get_fpu_tag ( st0_phys_idx ) == x86::FPU_TAG_EMPTY ||
					fpu.get_fpu_tag ( dst_phys_idx ) == x86::FPU_TAG_EMPTY ) {
				fsw_flags |= ( x86::FSW_IE | x86::FSW_SF );
				check_fpu_exception ( fpu.fpu_status_word, fpu.fpu_control_word, fsw_flags );
				return;
			}
			operand1 = fpu.fpu_stack [ dst_phys_idx ];
			operand2 = fpu.fpu_stack [ st0_phys_idx ];
		}
		else if ( instr.op0_kind ( ) == OpKindSimple::Register && instr.op0_reg ( ) == Register::ST0 &&
						instr.op1_kind ( ) == OpKindSimple::Register &&
						instr.op1_reg ( ) >= Register::ST0 && instr.op1_reg ( ) <= Register::ST7 ) {
			const int sti_phys_idx = fpu.get_fpu_phys_idx ( sti );
			if ( fpu.get_fpu_tag ( st0_phys_idx ) == x86::FPU_TAG_EMPTY ||
					fpu.get_fpu_tag ( sti_phys_idx ) == x86::FPU_TAG_EMPTY ) {
				fsw_flags |= ( x86::FSW_IE | x86::FSW_SF );
				check_fpu_exception ( fpu.fpu_status_word, fpu.fpu_control_word, fsw_flags );
				return;
			}
			operand1 = fpu.fpu_stack [ st0_phys_idx ];
			operand2 = fpu.fpu_stack [ sti_phys_idx ];
		}
		else {
			// !TODO(exception)
			return;
		}
	}
	else {
		// !TODO(exception)
		return;
	}

	if ( boost::multiprecision::fpclassify ( operand1 ) == FP_SUBNORMAL ||
			boost::multiprecision::fpclassify ( operand2 ) == FP_SUBNORMAL ) {
		fsw_flags |= x86::FSW_DE;
	}
	if ( boost::multiprecision::isnan ( operand1 ) || boost::multiprecision::isnan ( operand2 ) ||
			( boost::multiprecision::fpclassify ( operand1 ) == FP_ZERO && boost::multiprecision::fpclassify ( operand2 ) == FP_INFINITE ) ||
			( boost::multiprecision::fpclassify ( operand1 ) == FP_INFINITE && boost::multiprecision::fpclassify ( operand2 ) == FP_ZERO ) ) {
		fsw_flags |= x86::FSW_IE;
		check_fpu_exception ( fpu.fpu_status_word, fpu.fpu_control_word, fsw_flags );
		return;
	}

	result = operand1 * operand2;
	if ( boost::multiprecision::fpclassify ( result ) == FP_INFINITE ) {
		fsw_flags |= x86::FSW_OE;
	}
	if ( boost::multiprecision::fpclassify ( result ) == FP_SUBNORMAL ) {
		fsw_flags |= x86::FSW_DE;
	}
	if ( ( boost::multiprecision::fpclassify ( result ) == FP_SUBNORMAL || boost::multiprecision::fpclassify ( result ) == FP_ZERO ) &&
			boost::multiprecision::fpclassify ( operand1 ) == FP_NORMAL && boost::multiprecision::fpclassify ( operand2 ) == FP_NORMAL ) {
		fsw_flags |= x86::FSW_UE;
	}
	if ( !( fsw_flags & ( x86::FSW_OE | x86::FSW_UE ) ) && boost::multiprecision::fpclassify ( result ) != FP_ZERO ) {
		fsw_flags |= x86::FSW_PE;
	}

	fpu.fpu_status_word.C1 = 0;
	if ( fsw_flags & x86::FSW_IE && !( fsw_flags & x86::FSW_SF ) && fpu.fpu_control_word.IM ) {
		result = std::numeric_limits<float80_t>::quiet_NaN ( );
	}

	fpu.fpu_stack [ dst_phys_idx ] = result;
	fpu.set_fpu_tag ( dst_phys_idx, fpu.classify_fpu_operand ( result ) );
	if ( pop_stack ) {
		fpu.set_fpu_tag ( st0_phys_idx, x86::FPU_TAG_EMPTY );
		fpu.fpu_top = ( fpu.fpu_top + 1 ) % 8;
		fpu.update_fsw_top ( );
	}
	check_fpu_exception ( fpu.fpu_status_word, fpu.fpu_control_word, fsw_flags );
}

/// FNSTCW - Store FPU Control Word
/// Stores the 16-bit FPU control word to a memory location, without affecting flags.
void handlers::fnstcw ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_size ( );
	if ( instr.op0_kind ( ) != OpKindSimple::Memory || op_size != 2 ) {
		// !TODO(exception)
		return;
	}

	const uint64_t addr = helpers::get_operand_value<uint64_t> ( instr, 0u, context );
	const uint16_t control_word = context.get_fpu ( ).fpu_control_word.value;
	if ( context.is_within_stack_bounds ( addr, 2 ) ) {
		context.set_stack<uint16_t> ( addr, control_word );
	}
	else {
		context.set_memory<uint16_t> ( addr, control_word );
	}
}