# Contributing to LogLens Community

Thank you for your interest in contributing to LogLens Community!

LogLens Community is an open-source cybersecurity project designed to make Windows security logs easier to understand for beginners, students, and security analysts.

## Ways to Contribute

You can contribute by:

- Reporting bugs or unexpected behavior.
- Suggesting improvements to the user interface.
- Improving documentation and installation instructions.
- Proposing new Windows event detection rules.
- Adding tests or improving existing functionality.
- Helping make security findings easier to understand.

## Getting Started

1. Fork the LogLens Community repository.
2. Clone your fork to your computer.
3. Follow the installation instructions in `README.md`.
4. Create a new branch for your changes.
5. Make and test your changes.
6. Submit a pull request describing what you changed and why.

## Testing

Before submitting code changes, run:

```bash
python -m pytest
```

Make sure existing tests pass and add tests for new functionality where appropriate.

## Detection Rules

When contributing detection rules, include a clear description, relevant Windows Event IDs, severity, and MITRE ATT&CK mapping where applicable.

Detection rules should avoid unnecessary false positives and provide understandable explanations.

## Reporting Bugs

Open a GitHub Issue describing the problem, how to reproduce it, and what you expected to happen.

Please remove personal information, passwords, IP addresses, usernames, and other sensitive information from screenshots or logs before sharing them.

For security vulnerabilities, follow the instructions in `SECURITY.md` instead of opening a public issue.

## Code of Conduct

Be respectful, constructive, and welcoming to contributors of all experience levels.

## License

By contributing, you agree that your contributions will be licensed under the project's Apache License 2.0.