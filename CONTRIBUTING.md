# Contributing

Thanks for helping improve HECAVEX Radar.

1. Open an issue before large behavioral or data-contract changes.
2. Keep the project read-only and static. Do not add accounts, submissions, or browser-side calls to observed indicators.
3. Never commit live credentials, internal collector code, proprietary scoring logic, private HECAVEX history, or real victim data. Public defanged CertStream candidates may only use the documented archive schema.
4. Add Python tests for pipeline changes and Vitest tests for dashboard changes.
5. Create a Python 3.12 virtual environment, install `.[dev]`, install the pnpm dependencies, and run `pnpm check` before submitting a pull request.

Use reserved `.test`, `.example`, or documentation IP ranges in fixtures. Contributions are accepted under the Apache License 2.0.
