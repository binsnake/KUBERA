# Contributing to KUBERA

Thank you for your interest in contributing to KUBERA! We welcome contributions to improve this x86 software emulator. Please follow the guidelines below to ensure a smooth collaboration.

## How to Contribute

1. **Fork the Repository**: Create a fork of the [KUBERA repository](https://github.com/[your-repo]/kubera) on GitHub.
2. **Clone Your Fork**: Clone your fork to your local machine.
3. **Create a Branch**: Use a descriptive branch name (e.g., `feature/add-avx512-support` or `fix/memory-leak`).
4. **Make Changes**: Implement your feature, bug fix, or improvement.
5. **Test Your Changes**: Ensure your changes work as intended and do not introduce new issues. Test within an isolated VM environment.
6. **Commit Changes**: Write clear, concise commit messages following the [Conventional Commits](https://www.conventionalcommits.org/) format (e.g., `feat: add AVX512 emulation support`).
7. **Push to Your Fork**: Push your branch to your forked repository.
8. **Submit a Pull Request**: Open a pull request (PR) against the main repository’s `main` branch. Include a detailed description of your changes and reference any related issues.

## Code Style and Formatting

- Follow the formatting rules specified in the [`.editorconfig`](.editorconfig) file. Use an editor that supports EditorConfig to enforce these settings.
- Write clean, readable code with meaningful variable names and comments where necessary.
- Ensure consistency with the existing codebase (e.g., use spaces, not tabs, and follow naming conventions).

## Contribution Guidelines

- **Scope**: Contributions should align with KUBERA’s goals (x86 emulation, detailed analysis, isolation). Major feature proposals should be discussed in an issue first.
- **Testing**: Test your changes thoroughly, especially for edge cases involving different x86 architectures or operating systems. Include test cases if applicable.
- **Documentation**: Update relevant documentation (e.g., README, code comments) for new features or changes.
- **Licensing**: By contributing, you agree that your contributions are licensed under the [Creative Commons Attribution-NonCommercial 4.0 International License](https://creativecommons.org/licenses/by-nc/4.0/), as specified in the [LICENSE](LICENSE) file.

## Reporting Issues

- Use the GitHub Issues tab to report bugs or suggest features.
- Provide a clear title, detailed description, steps to reproduce (for bugs), and any relevant logs or screenshots.
- Check for existing issues to avoid duplicates.

## Code of Conduct

- Be respectful and inclusive in all interactions.
- Follow GitHub’s [Community Guidelines](https://docs.github.com/en/site-policy/github-terms/github-community-guidelines).
- Avoid submitting code that violates third-party intellectual property rights or introduces security risks.

## Contact

For questions or clarification, contact REAPS, s.r.o. at reapsgg@proton.me. For significant changes, open an issue to discuss before starting work.

Thank you for helping make KUBERA better!