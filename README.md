# KUBERA
KUBERA is a concrete x86 software emulator focused on detailed analysis and control, primarily for Windows binaries, with planned support for Linux and other operating systems. It is aiming to be platform-independent, designed for research, and not intended for full system emulation.

Disclaimer: This project is heavily work-in-progress. Development has been ongoing for several months.

## Purpose
KUBERA provides deterministic, reversible, and verbose emulation, offering maximum insight into execution flow, including stack, memory, and register changes. It includes a user-friendly SDK to intercept operations and aims to prevent emulation detection by software. Key use cases:

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
KUBERA is not a secure sandbox for malicious software. It may allow host data access or VM escapes, potentially enabling malicious code execution. Always run KUBERA and emulated applications in an isolated environment (e.g., VMWare, VirtualBox, QEMU). KUBERA is a research tool in early development, not sponsored, and not guaranteed to be safe or complete.
Third-Party Software
KUBERA references third-party software names for binary initialization. These names and binaries are the property of their respective legal entities or developers, and REAPS, s.r.o. claims no ownership. No binaries are distributed with this project.

## Dependencies
KUBERA includes the following open-source libraries:

ImGui - Licensed under the MIT License.
Capstone - Licensed under the BSD 3-Clause License.

See the LICENSE file for full license texts and copyright notices.
## License
This project is licensed under the MIT license, effective from the commit including the LICENSE file. See the LICENSE file for details.

## Contributing
Contributions are welcome! Please follow the naming conventions and formatting specified in the .editorconfig file. For detailed guidelines, see CONTRIBUTING.md (if available) or contact REAPS, s.r.o.

## Contact
For commercial inquiries, licensing questions, or issues, contact REAPS, s.r.o. at reapsgg@proton.me.

Disclaimer
KUBERA is provided "as is" for research purposes only. REAPS, s.r.o. is not liable for any damages, data loss, or security breaches resulting from its use. Users are responsible for ensuring compliance with all applicable laws and third-party intellectual property rights when using KUBERA or emulating third-party software.

## Community

We're currently on discord: https://discord.gg/6HyQYzPpyN
