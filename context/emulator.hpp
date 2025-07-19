#pragma once

#include "KUBERA.hpp"
namespace kubera
{
  namespace handlers
  {
    // Arithmetic Instructions
    void add ( const iced::Instruction& instr, KUBERA& context );
    void sub ( const iced::Instruction& instr, KUBERA& context );
    void inc ( const iced::Instruction& instr, KUBERA& context );
    void dec ( const iced::Instruction& instr, KUBERA& context );
    void mul ( const iced::Instruction& instr, KUBERA& context );
    void imul ( const iced::Instruction& instr, KUBERA& context );
    void div ( const iced::Instruction& instr, KUBERA& context );
    void idiv ( const iced::Instruction& instr, KUBERA& context );
    void adc ( const iced::Instruction& instr, KUBERA& context );
    void sbb ( const iced::Instruction& instr, KUBERA& context );
    void neg ( const iced::Instruction& instr, KUBERA& context );
    void xadd ( const iced::Instruction& instr, KUBERA& context );
    void cdq ( const iced::Instruction& instr, KUBERA& context );
    void cdqe ( const iced::Instruction& instr, KUBERA& context );
    void cwd ( const iced::Instruction& instr, KUBERA& context );
    void cqo ( const iced::Instruction& instr, KUBERA& context );
    void cwde ( const iced::Instruction& instr, KUBERA& context );
    void cbw ( const iced::Instruction& instr, KUBERA& context );

    // Bitwise and Logical Instructions
    void and_ ( const iced::Instruction& instr, KUBERA& context );
    void or_ ( const iced::Instruction& instr, KUBERA& context );
    void xor_ ( const iced::Instruction& instr, KUBERA& context );
    void not_ ( const iced::Instruction& instr, KUBERA& context );
    void shl ( const iced::Instruction& instr, KUBERA& context );
    void sal ( const iced::Instruction& instr, KUBERA& context );
    void sar ( const iced::Instruction& instr, KUBERA& context );
    void shr ( const iced::Instruction& instr, KUBERA& context );
    void shld ( const iced::Instruction& instr, KUBERA& context );
    void shrd ( const iced::Instruction& instr, KUBERA& context );
    void rol ( const iced::Instruction& instr, KUBERA& context );
    void ror ( const iced::Instruction& instr, KUBERA& context );
    void rcl ( const iced::Instruction& instr, KUBERA& context );
    void rcr ( const iced::Instruction& instr, KUBERA& context );

    // Conditional Move Instructions
    void cmovo ( const iced::Instruction& instr, KUBERA& context );
    void cmovb ( const iced::Instruction& instr, KUBERA& context );
    void cmovnl ( const iced::Instruction& instr, KUBERA& context );
    void cmovbe ( const iced::Instruction& instr, KUBERA& context );
    void cmovz ( const iced::Instruction& instr, KUBERA& context );
    void cmovle ( const iced::Instruction& instr, KUBERA& context );
    void cmovl ( const iced::Instruction& instr, KUBERA& context );
    void cmovnp ( const iced::Instruction& instr, KUBERA& context );
    void cmovns ( const iced::Instruction& instr, KUBERA& context );
    void cmovp ( const iced::Instruction& instr, KUBERA& context );
    void cmovnb ( const iced::Instruction& instr, KUBERA& context );
    void cmovno ( const iced::Instruction& instr, KUBERA& context );
    void cmovs ( const iced::Instruction& instr, KUBERA& context );
    void cmovnz ( const iced::Instruction& instr, KUBERA& context );
    void cmovnbe ( const iced::Instruction& instr, KUBERA& context );
    void cmovnle ( const iced::Instruction& instr, KUBERA& context );

    // Set Based on Condition Instructions
    void setb ( const iced::Instruction& instr, KUBERA& context );
    void setnp ( const iced::Instruction& instr, KUBERA& context );
    void sets ( const iced::Instruction& instr, KUBERA& context );
    void setnl ( const iced::Instruction& instr, KUBERA& context );
    void seto ( const iced::Instruction& instr, KUBERA& context );
    void setbe ( const iced::Instruction& instr, KUBERA& context );
    void setz ( const iced::Instruction& instr, KUBERA& context );
    void setnb ( const iced::Instruction& instr, KUBERA& context );
    void setno ( const iced::Instruction& instr, KUBERA& context );
    void setp ( const iced::Instruction& instr, KUBERA& context );
    void setle ( const iced::Instruction& instr, KUBERA& context );
    void setnle ( const iced::Instruction& instr, KUBERA& context );
    void setns ( const iced::Instruction& instr, KUBERA& context );
    void setl ( const iced::Instruction& instr, KUBERA& context );
    void setnbe ( const iced::Instruction& instr, KUBERA& context );
    void setnz ( const iced::Instruction& instr, KUBERA& context );

    // Bit Manipulation Instructions
    void bzhi ( const iced::Instruction& instr, KUBERA& context );
    void andn ( const iced::Instruction& instr, KUBERA& context );
    void bextr ( const iced::Instruction& instr, KUBERA& context );
    void popcnt ( const iced::Instruction& instr, KUBERA& context );
    void bswap ( const iced::Instruction& instr, KUBERA& context );
    void bt ( const iced::Instruction& instr, KUBERA& context );
    void bts ( const iced::Instruction& instr, KUBERA& context );
    void btr ( const iced::Instruction& instr, KUBERA& context );
    void btc ( const iced::Instruction& instr, KUBERA& context );
    void bsr ( const iced::Instruction& instr, KUBERA& context );
    void bsf ( const iced::Instruction& instr, KUBERA& context );
    void tzcnt ( const iced::Instruction& instr, KUBERA& context );

    // Comparison and Test Instructions
    void cmp ( const iced::Instruction& instr, KUBERA& context );
    void test ( const iced::Instruction& instr, KUBERA& context );
    void cmpxchg ( const iced::Instruction& instr, KUBERA& context );
    void cmpxchg16b ( const iced::Instruction& instr, KUBERA& context );

    // Control Flow Instructions
    void jmp ( const iced::Instruction& instr, KUBERA& context );
    void je ( const iced::Instruction& instr, KUBERA& context );
    void jne ( const iced::Instruction& instr, KUBERA& context );
    void jnbe ( const iced::Instruction& instr, KUBERA& context );
    void jg ( const iced::Instruction& instr, KUBERA& context );
    void jl ( const iced::Instruction& instr, KUBERA& context );
    void jnb ( const iced::Instruction& instr, KUBERA& context );
    void jb ( const iced::Instruction& instr, KUBERA& context );
    void jns ( const iced::Instruction& instr, KUBERA& context );
    void jnl ( const iced::Instruction& instr, KUBERA& context );
    void jo ( const iced::Instruction& instr, KUBERA& context );
    void jno ( const iced::Instruction& instr, KUBERA& context );
    void jbe ( const iced::Instruction& instr, KUBERA& context );
    void js ( const iced::Instruction& instr, KUBERA& context );
    void ja ( const iced::Instruction& instr, KUBERA& context );
    void jae ( const iced::Instruction& instr, KUBERA& context );
    void jge ( const iced::Instruction& instr, KUBERA& context );
    void jle ( const iced::Instruction& instr, KUBERA& context );
    void jp ( const iced::Instruction& instr, KUBERA& context );
    void jnp ( const iced::Instruction& instr, KUBERA& context );
    void jcxz ( const iced::Instruction& instr, KUBERA& context );
    void jecxz ( const iced::Instruction& instr, KUBERA& context );
    void jrcxz ( const iced::Instruction& instr, KUBERA& context );
    void call ( const iced::Instruction& instr, KUBERA& context );
    void ret ( const iced::Instruction& instr, KUBERA& context );
    void iret ( const iced::Instruction& instr, KUBERA& context );
    void iretd ( const iced::Instruction& instr, KUBERA& context );
    void iretq ( const iced::Instruction& instr, KUBERA& context );

    // Stack and Frame Instructions
    void enter ( const iced::Instruction& instr, KUBERA& context );
    void leave ( const iced::Instruction& instr, KUBERA& context );
    void push ( const iced::Instruction& instr, KUBERA& context );
    void pop ( const iced::Instruction& instr, KUBERA& context );
    void pushfq ( const iced::Instruction& instr, KUBERA& context );
    void popfq ( const iced::Instruction& instr, KUBERA& context );

    // System Instructions
    void cli ( const iced::Instruction& instr, KUBERA& context );
    void cld ( const iced::Instruction& instr, KUBERA& context );
    void clc ( const iced::Instruction& instr, KUBERA& context );
    void clui ( const iced::Instruction& instr, KUBERA& context );
    void cmc ( const iced::Instruction& instr, KUBERA& context );
    void stc ( const iced::Instruction& instr, KUBERA& context );
    void sti ( const iced::Instruction& instr, KUBERA& context );
    void std ( const iced::Instruction& instr, KUBERA& context );
    void rdtsc ( const iced::Instruction& instr, KUBERA& context );
    void cpuid ( const iced::Instruction& instr, KUBERA& context );
    void xgetbv ( const iced::Instruction& instr, KUBERA& context );
    void hlt ( const iced::Instruction& instr, KUBERA& context );
    void int1 ( const iced::Instruction& instr, KUBERA& context );
    void int3 ( const iced::Instruction& instr, KUBERA& context );
    void int_ ( const iced::Instruction& instr, KUBERA& context );
    void fxsave ( const iced::Instruction& instr, KUBERA& context );
    void fxrstor ( const iced::Instruction& instr, KUBERA& context );
    void stmxcsr ( const iced::Instruction& instr, KUBERA& context );
    void ldmxcsr ( const iced::Instruction& instr, KUBERA& context );
    void sahf ( const iced::Instruction& instr, KUBERA& context );
    void lahf ( const iced::Instruction& instr, KUBERA& context );
    void pushf ( const iced::Instruction& instr, KUBERA& context );
    void popf ( const iced::Instruction& instr, KUBERA& context );
    void syscall ( const iced::Instruction& instr, KUBERA& context );

    // Data Movement Instructions
    void mov ( const iced::Instruction& instr, KUBERA& context );
    void movd ( const iced::Instruction& instr, KUBERA& context );
    void movq ( const iced::Instruction& instr, KUBERA& context );
    void movabs ( const iced::Instruction& instr, KUBERA& context );
    void movsxd ( const iced::Instruction& instr, KUBERA& context );
    void movzx ( const iced::Instruction& instr, KUBERA& context );
    void movsx ( const iced::Instruction& instr, KUBERA& context );
    void movaps ( const iced::Instruction& instr, KUBERA& context );
    void movups ( const iced::Instruction& instr, KUBERA& context );
    void lea ( const iced::Instruction& instr, KUBERA& context );
    void xchg ( const iced::Instruction& instr, KUBERA& context );

    // String Operations
    void movs ( const iced::Instruction& instr, KUBERA& context );
    void movsw ( const iced::Instruction& instr, KUBERA& context );
    void movsb ( const iced::Instruction& instr, KUBERA& context );
    void movsd ( const iced::Instruction& instr, KUBERA& context );
    void movsq ( const iced::Instruction& instr, KUBERA& context );
    void stos ( const iced::Instruction& instr, KUBERA& context );

    // SIMD Instructions
    void vpxor ( const iced::Instruction& instr, KUBERA& context );
    void vpcmpeqw ( const iced::Instruction& instr, KUBERA& context );
    void vpmovmskb ( const iced::Instruction& instr, KUBERA& context );
    void vzeroupper ( const iced::Instruction& instr, KUBERA& context );
    void vinsertf128 ( const iced::Instruction& instr, KUBERA& context );
    void vmovups ( const iced::Instruction& instr, KUBERA& context );
    void vmovaps ( const iced::Instruction& instr, KUBERA& context );
    void vmovdqu ( const iced::Instruction& instr, KUBERA& context );
    void movdqu ( const iced::Instruction& instr, KUBERA& context );
    void movlhps ( const iced::Instruction& instr, KUBERA& context );
    void punpcklqdq ( const iced::Instruction& instr, KUBERA& context );
    void prefetchw ( const iced::Instruction& instr, KUBERA& context );
    void psrldq ( const iced::Instruction& instr, KUBERA& context );
    void movhlps ( const iced::Instruction& instr, KUBERA& context );
    void unpcklps ( const iced::Instruction& instr, KUBERA& context );
    void pinsrb ( const iced::Instruction& instr, KUBERA& context );
    void pinsrd ( const iced::Instruction& instr, KUBERA& context );
    void pinsrq ( const iced::Instruction& instr, KUBERA& context );

    void paddb(const iced::Instruction& instr, KUBERA& context);
    void paddw(const iced::Instruction& instr, KUBERA& context);
    void paddd(const iced::Instruction& instr, KUBERA& context);
    void paddq(const iced::Instruction& instr, KUBERA& context);

    // Floating-Point Instructions
    void addss ( const iced::Instruction& instr, KUBERA& context );
    void subss ( const iced::Instruction& instr, KUBERA& context );
    void mulss ( const iced::Instruction& instr, KUBERA& context );
    void divss ( const iced::Instruction& instr, KUBERA& context );
    void minss ( const iced::Instruction& instr, KUBERA& context );
    void maxss ( const iced::Instruction& instr, KUBERA& context );
    void andps ( const iced::Instruction& instr, KUBERA& context );
    void orps ( const iced::Instruction& instr, KUBERA& context );
    void xorps ( const iced::Instruction& instr, KUBERA& context );
    void sqrtss ( const iced::Instruction& instr, KUBERA& context );
    void sqrtsd ( const iced::Instruction& instr, KUBERA& context );
    void comiss ( const iced::Instruction& instr, KUBERA& context );
    void ucomiss ( const iced::Instruction& instr, KUBERA& context );
    void comisd ( const iced::Instruction& instr, KUBERA& context );
    void cmpss ( const iced::Instruction& instr, KUBERA& context );
    void cvtss2si ( const iced::Instruction& instr, KUBERA& context );
    void cvttss2si ( const iced::Instruction& instr, KUBERA& context );
    void cvtsi2ss ( const iced::Instruction& instr, KUBERA& context );
    void cvtsi2sd ( const iced::Instruction& instr, KUBERA& context );
    void cvtss2sd ( const iced::Instruction& instr, KUBERA& context );
    void cvtsd2ss ( const iced::Instruction& instr, KUBERA& context );
    void roundss ( const iced::Instruction& instr, KUBERA& context );
    void rcpss ( const iced::Instruction& instr, KUBERA& context );
    void rsqrtss ( const iced::Instruction& instr, KUBERA& context );
    void mulsd ( const iced::Instruction& instr, KUBERA& context );
    void movss ( const iced::Instruction& instr, KUBERA& context );

    // 80-bit floating point instructions
    void fld ( const iced::Instruction& instr, KUBERA& context );
    void fprem ( const iced::Instruction& instr, KUBERA& context );
    void fstp ( const iced::Instruction& instr, KUBERA& context );
    void ffree ( const iced::Instruction& instr, KUBERA& context );
    void fincstp ( const iced::Instruction& instr, KUBERA& context );
    void fmul ( const iced::Instruction& instr, KUBERA& context );
    void fnstcw ( const iced::Instruction& instr, KUBERA& context );

    // Miscellaneous Instructions
    void nop ( const iced::Instruction& instr, KUBERA& context );
  };
};