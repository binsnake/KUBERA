#pragma once

#include <cstdint>

namespace x86
{
	// RFLAGS Register (64 bits)
	union Flags {
		std::uint64_t value;
		struct {
			std::uint64_t CF : 1;					// Carry Flag
			std::uint64_t reserved1 : 1;		// Reserved (always 1)
			std::uint64_t PF : 1;					// Parity Flag
			std::uint64_t reserved3 : 1;		// Reserved (0)
			std::uint64_t AF : 1;					// Auxiliary Carry Flag
			std::uint64_t reserved5 : 1;		// Reserved (0)
			std::uint64_t ZF : 1;					// Zero Flag
			std::uint64_t SF : 1;					// Sign Flag
			std::uint64_t TF : 1;					// Trap Flag
			std::uint64_t IF : 1;					// Interrupt Enable Flag
			std::uint64_t DF : 1;					// Direction Flag
			std::uint64_t OF : 1;					// Overflow Flag
			std::uint64_t IOPL : 2;				// I/O Privilege Level
			std::uint64_t NT : 1;					// Nested Task Flag
			std::uint64_t reserved15 : 1;  // Reserved (0)
			std::uint64_t RF : 1;					// Resume Flag
			std::uint64_t VM : 1;					// Virtual-8086 Mode
			std::uint64_t AC : 1;					// Alignment Check / Access Control
			std::uint64_t VIF : 1;					// Virtual Interrupt Flag
			std::uint64_t VIP : 1;					// Virtual Interrupt Pending
			std::uint64_t ID : 1;					// ID Flag
			std::uint64_t reserved22_63 : 41;  // Reserved (0)
		};
	};

	// MXCSR Register (32 bits)
	union Mxcsr {
		std::uint32_t value;
		struct {
			unsigned int IE : 1;   // Invalid Operation Flag
			unsigned int DE : 1;   // Denormal Flag
			unsigned int ZE : 1;   // Divide-by-Zero Flag
			unsigned int OE : 1;   // Overflow Flag
			unsigned int UE : 1;   // Underflow Flag
			unsigned int PE : 1;   // Precision Flag
			unsigned int DAZ : 1;  // Denormals Are Zeros Flag
			unsigned int IM : 1;   // Invalid Operation Mask
			unsigned int DM : 1;   // Denormal Mask
			unsigned int ZM : 1;   // Divide-by-Zero Mask
			unsigned int OM : 1;   // Overflow Mask
			unsigned int UM : 1;   // Underflow Mask
			unsigned int PM : 1;   // Precision Mask
			unsigned int RC : 2;   // Rounding Control
			unsigned int FTZ : 1;  // Flush To Zero Flag
			unsigned int reserved : 16;  // Reserved
		};
	};

	// x87 FPU Control Word (16 bits)
	union FPUControlWord {
		std::uint16_t value;
		struct {
			unsigned int IM : 1;  // Invalid Operation Mask
			unsigned int DM : 1;  // Denormal Operand Mask
			unsigned int ZM : 1;  // Divide-by-Zero Mask
			unsigned int OM : 1;  // Overflow Mask
			unsigned int UM : 1;  // Underflow Mask
			unsigned int PM : 1;  // Precision Mask
			unsigned int reserved6 : 1;  // Reserved
			unsigned int reserved7 : 1;  // Reserved
			unsigned int PC : 2;  // Precision Control
			unsigned int RC : 2;  // Rounding Control
			unsigned int IC : 1;  // Infinity Control (legacy)
			unsigned int reserved13 : 3;  // Reserved
		};
	};

	// x87 FPU Status Word (16 bits)
	union FPUStatusWord {
		std::uint16_t value;
		struct {
			unsigned int IE : 1;  // Invalid Operation Flag
			unsigned int DE : 1;  // Denormal Operand Flag
			unsigned int ZE : 1;  // Divide-by-Zero Flag
			unsigned int OE : 1;  // Overflow Flag
			unsigned int UE : 1;  // Underflow Flag
			unsigned int PE : 1;  // Precision Flag
			unsigned int SF : 1;  // Stack Fault Flag
			unsigned int ES : 1;  // Exception Summary Status Flag
			unsigned int C0 : 1;  // Condition Code 0
			unsigned int C1 : 1;  // Condition Code 1
			unsigned int C2 : 1;  // Condition Code 2
			unsigned int TOP : 3; // Top of Stack Pointer
			unsigned int C3 : 1;  // Condition Code 3
			unsigned int B : 1;   // Busy Flag
		};
	};

	// x87 FPU Tag Word (16 bits)
	union FPUTagWord {
		std::uint16_t value;
		struct {
			unsigned int TAG0 : 2;  // Tag for ST(0): 00=Valid, 01=Zero, 10=Special, 11=Empty
			unsigned int TAG1 : 2;  // Tag for ST(1): 00=Valid, 01=Zero, 10=Special, 11=Empty
			unsigned int TAG2 : 2;  // Tag for ST(2): 00=Valid, 01=Zero, 10=Special, 11=Empty
			unsigned int TAG3 : 2;  // Tag for ST(3): 00=Valid, 01=Zero, 10=Special, 11=Empty
			unsigned int TAG4 : 2;  // Tag for ST(4): 00=Valid, 01=Zero, 10=Special, 11=Empty
			unsigned int TAG5 : 2;  // Tag for ST(5): 00=Valid, 01=Zero, 10=Special, 11=Empty
			unsigned int TAG6 : 2;  // Tag for ST(6): 00=Valid, 01=Zero, 10=Special, 11=Empty
			unsigned int TAG7 : 2;  // Tag for ST(7): 00=Valid, 01=Zero, 10=Special, 11=Empty
		};
	};

	static constexpr uint8_t FPU_TAG_VALID = 0b00;
	static constexpr uint8_t FPU_TAG_ZERO = 0b01;
	static constexpr uint8_t FPU_TAG_SPECIAL = 0b10;
	static constexpr uint8_t FPU_TAG_EMPTY = 0b11;
	static constexpr uint16_t FSW_IE = ( 1 << 0 );
	static constexpr uint16_t FSW_DE = ( 1 << 1 );
	static constexpr uint16_t FSW_ZE = ( 1 << 2 );
	static constexpr uint16_t FSW_OE = ( 1 << 3 );
	static constexpr uint16_t FSW_UE = ( 1 << 4 );
	static constexpr uint16_t FSW_PE = ( 1 << 5 );
	static constexpr uint16_t FSW_SF = ( 1 << 6 );
	static constexpr uint16_t FSW_ES = ( 1 << 7 );
	static constexpr uint16_t FSW_C0 = ( 1 << 8 );
	static constexpr uint16_t FSW_C1 = ( 1 << 9 );
	static constexpr uint16_t FSW_C2 = ( 1 << 10 );
	static constexpr uint16_t FSW_TOP_SHIFT = 11;
	static constexpr uint16_t FSW_TOP_MASK = ( 0b111 << FSW_TOP_SHIFT );
	static constexpr uint16_t FSW_C3 = ( 1 << 14 );
	static constexpr uint16_t FSW_B = ( 1 << 15 );
	static constexpr uint16_t FCW_IM = ( 1 << 0 );
	static constexpr uint16_t FCW_DM = ( 1 << 1 );
	static constexpr uint16_t FCW_ZM = ( 1 << 2 );
	static constexpr uint16_t FCW_OM = ( 1 << 3 );
	static constexpr uint16_t FCW_UM = ( 1 << 4 );
	static constexpr uint16_t FCW_PM = ( 1 << 5 );
	static constexpr uint16_t FCW_PC_SHIFT = 8;
	static constexpr uint16_t FCW_PC_MASK = ( 0b11 << FCW_PC_SHIFT );
	static constexpr uint16_t FCW_RC_SHIFT = 10;
	static constexpr uint16_t FCW_RC_MASK = ( 0b11 << FCW_RC_SHIFT );
};