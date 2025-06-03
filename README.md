# KUBERA
KUBERA is a concrete x86_64 software emulator focused on detailed analysis and control, primarily for Windows binaries, with planned support for Linux and other operating systems. 
It is aiming to be platform-independent, designed for research, and not intended for full system emulation.


Disclaimer: This project is heavily work-in-progress. Development has been ongoing for several months.

## Purpose
KUBERA provides deterministic, reversible, and verbose emulation, offering maximum insight into execution flow, including stack, memory, and register changes. 
It includes a user-friendly SDK to intercept operations and aims to prevent emulation detection by software. Key use cases:

Analyze software interactions with operating systems.

Inspect functionality at the instruction level.

Emulate x86 software natively, including extensions (AVX2, AVX512, APX) on legacy hardware.

Examine edge cases across x86 CPU architectures (contribution-dependent).


## Features

Detailed execution tracing (stack, memory, registers).

Platform-independent emulation of Windows and Linux binaries.

Support for x86 extensions on unsupported hardware.

SDK for operation interception and analysis.

Focus on isolation (ongoing development).

## Usage Warnings
KUBERA is not a secure sandbox for malicious software. It may allow host data access or VM escapes, potentially enabling malicious code execution. 

Always run KUBERA and emulated applications in an isolated environment (e.g., VMWare, VirtualBox, QEMU). 

KUBERA is a research tool in early development, not sponsored, and not guaranteed to be safe or complete.

Third-Party Software

KUBERA references third-party software names for binary initialization. These names and binaries are the property of their respective legal entities or developers, and REAPS, s.r.o. claims no ownership. No binaries are distributed with this project.

A lot of the code is very experimental and prone to failure. KUBERA is mostly an ongoing learning project towards CPU & OS internals.

## Dependencies
KUBERA includes the following open-source libraries:

ImGui - Licensed under the MIT License.

Capstone - Licensed under the BSD 3-Clause License.

Boost libraries - Licensed under the BSL-1.0 License.

See the LICENSE file for full license texts and copyright notices.

## License
This project is licensed under the MIT license, effective from the commit including the LICENSE file. See the LICENSE file for details.

## Tests
It is recommended that new instructions are tested vs hardware, we use https://github.com/ZehMatt/x86Tester/ to generate instruction combinations that we test our framework against.

## Contributing
Contributions are welcome! Please follow the naming conventions and formatting specified in the .editorconfig file. For detailed guidelines, see CONTRIBUTING.md (if available) or contact REAPS, s.r.o.

## Similar projects

https://github.com/icicle-emu/icicle-emu - Icicle is an emulator written in Rust
https://github.com/unicorn-engine/unicorn

## Usage Disclaimer

KUBERA is provided "as is" for research purposes only. REAPS, s.r.o. is not liable for any damages, data loss, or security breaches resulting from its use. Users are responsible for ensuring compliance with all applicable laws and third-party intellectual property rights when using KUBERA or emulating third-party software.

## Artificially generated content disclaimer

Parts of KUBERA were made with AI-assistance, in the form of full-project context with Gemini 2.5 Pro.
Due to this reason, 'semantics' can't fall under the MIT license. For clarity, semantics will include the 'Unlicense'.

Gemini's large context window allows for importing the entire project into it.
While generally AI generated code leads to many inaccuracies, Gemini 2.5 Pro & Flash managed to pass tests against real hardware.
Gemini code can usually be identified by the comments surrounding it, as it's generally very verbose.

However, AI-generated code suffers from poor performance within the existing architecture, redundant & expensive operations.
While this is initially okay, because it accelerates development significantly, and allows to check for hard-to-spot issues, in the long run the instruction handlers need to be re-written completely to run faster.

