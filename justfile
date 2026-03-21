# VulnersDotNet

# Format all code with CSharpier
format:
    dotnet csharpier format .

# Check formatting without changes
check-format:
    dotnet csharpier check .

# Build the solution
build:
    dotnet build

# Run all tests (unit tests always pass; integration tests require VULNERS_API_KEY)
test:
    dotnet test

# Run unit tests only (no external dependencies needed)
test-unit:
    dotnet test --filter "FullyQualifiedName~ValidationTests"

# Build + format + all tests (unit tests verify SDK behavior; integration tests skip without VULNERS_API_KEY)
ci: build check-format test

# Full CI with live API verification (requires VULNERS_API_KEY env var)
ci-integration: build check-format test

# Restore tools (CSharpier etc.)
restore-tools:
    dotnet tool restore
