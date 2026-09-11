# Capitec Fraud Engine Test Suite

An **xUnit test suite** covering rule evaluation, security utilities, and dummy file generation pipeline logic for the Capitec Fraud Engine backend.

---

## Key Test Modules

### 1. Fraud Rule & Banking Domain Evaluation
- **Directional & Boundary Guards**  
  Validates `NumericRuleEvaluator` threshold operations (`>`, `<`, `==`, `<=`, `>=`) and enforces directional guards so inbound deposits never trigger negative outbound debit rules.  
- **AML & Boundary Scenarios**  
  Tests exact boundary hits, zero-amount transactions, and structuring scenarios operating just below reporting thresholds.  
- **Multi-Rule Execution**  
  Verifies that `FraudEvaluationEngine` correctly evaluates multiple active rules concurrently and returns the complete set of broken rule IDs.  

### 2. Security Utilities
- **SHA-256 Password Hashing**  
  Validates `SecurityUtils.HashPasswordSha256` for deterministic 64-character hex string output, consistency, and safe handling of empty or whitespace strings.  

### 3. Dummy File Ingestion & Integration
- **CSV Format Validation**  
  Confirms `DummyFileGenerator` generates well-formed CSV files containing expected headers (`TransactionId`, `AccountNumber`, `Amount`, `TransactionType`).  
- **Pipeline Integration**  
  Parses generated CSVs into `TransactionRecord` domain models and evaluates them through the engine to ensure no false-positive alerts are triggered.  

---

## Setup & Resource Lifecycle
- **Isolated Test Environments**  
  Dynamically creates unique temporary folders per test run using `CreateTempTestDirectory()`.  
- **Automated Cleanup**  
  Implements `IDisposable` to recursively purge all temporary directories upon test completion.  

---

## Running the Tests

Run the test suite using the .NET CLI:

```bash
dotnet test --filter "FullyQualifiedName~FraudEngine.Tests"
