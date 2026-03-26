# Contributing

Thanks for your interest in contributing.

## Development Setup

1. Install VS Code + PlatformIO extension, or PlatformIO CLI.
2. Clone the repository.
3. Build firmware:

```powershell
pio run
```

4. Upload firmware:

```powershell
pio run -t upload --upload-port COM3
```

5. Monitor serial output:

```powershell
pio device monitor --port COM3 -b 115200
```

## Coding Guidelines

- Keep changes focused and minimal.
- Do not hardcode production keys in source files.
- Preserve existing coding style.
- Update README when behavior or setup changes.

## Pull Request Process

1. Create a feature branch from `main`.
2. Keep commits small and descriptive.
3. Ensure the project builds successfully.
4. Include logs/screenshots for hardware behavior changes.
5. Open a PR using the provided template.

## Reporting Bugs

- Use the bug report issue template.
- Include board type, PN532 wiring mode, COM port setup, and logs.
