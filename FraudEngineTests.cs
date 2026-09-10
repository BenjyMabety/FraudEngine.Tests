using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using Xunit;
using CapitecFraudEngine;
using CapitecFraudEngine.Infrastructure;
using CapitecFraudEngine.Domain;

namespace FraudEngine.Tests
{
    public class FraudEngineTests : IDisposable
    {
        private readonly NumericRuleEvaluator _numericEvaluator;
        private readonly List<string> _tempDirectoriesToClean;

        public FraudEngineTests()
        {
            _numericEvaluator = new NumericRuleEvaluator();
            _tempDirectoriesToClean = new List<string>();
        }

        public void Dispose()
        {
            foreach (var dir in _tempDirectoriesToClean)
            {
                if (Directory.Exists(dir))
                {
                    try
                    {
                        Directory.Delete(dir, recursive: true);
                    }
                    catch
                    {
                        // Ignore cleanup exceptions during test disposal
                    }
                }
            }
        }

        private string CreateTempTestDirectory()
        {
            string tempDir = Path.Combine(Path.GetTempPath(), "FraudEngineTestRun_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            _tempDirectoriesToClean.Add(tempDir);
            return tempDir;
        }

        #region 1. Basic & Banking Domain Fraud Rule Evaluation Tests

        [Theory]
        // Standard Threshold Tests
        [InlineData(-2001.00, "-2000", "<", 4, true)]   // Outbound > 2k threshold -> Broken
        [InlineData(-1999.00, "-2000", "<", 4, false)]  // Outbound < 2k threshold -> Not broken
        [InlineData(3500.00, "-2000", "<", 1, false)]   // Inbound Deposit -> Skipped (Direction Guard)
        [InlineData(-85000.00, "-50000", "<", 2, true)] // High withdrawal -> Broken
        [InlineData(300000.00, "250000", ">", 1, true)] // High deposit -> Broken

        // Banking Domain Specific Boundary & Structuring Scenarios
        [InlineData(-2000.00, "-2000", "<=", 4, true)]  // Exact boundary threshold match
        [InlineData(-1999.99, "-2000", "<=", 4, false)] // Structuring check just below reporting threshold
        [InlineData(-49999.99, "-50000", "<", 2, false)]// Anti-Money Laundering (AML) threshold avoidance
        [InlineData(0.00, "0", "==", 4, true)]          // Zero-amount exact equality match -> Broken
        public void NumericRuleEvaluator_EvaluatesDirectionAndThresholdsCorrectly(
            decimal amount, string threshold, string op, int transactionType, bool expectedBroken)
        {
            // Arrange
            var record = new TransactionRecord { Amount = amount, TransactionType = transactionType };
            var rule = new FraudRule
            {
                FieldName = "Amount",
                Operator = op,
                ThresholdValue = threshold
            };

            // Act
            bool isBroken = _numericEvaluator.IsBroken(record, rule);

            // Assert
            Assert.Equal(expectedBroken, isBroken);
        }

        [Fact]
        public void FraudEngine_EvaluatesMultipleActiveRules_ReturnsAllBrokenRuleIds()
        {
            // Arrange
            var engine = new FraudEvaluationEngine(new IFraudRuleEvaluator[] { _numericEvaluator });
            var record = new TransactionRecord
            {
                TransactionId = "TX-9901",
                AccountNumber = "ACC-100293",
                Amount = -75000.00m,
                TransactionType = 2 // Withdrawal
            };

            var activeRules = new List<FraudRule>
            {
                new FraudRule { RuleId = 1, FieldName = "Amount", Operator = "<", ThresholdValue = "-50000" }, // High Withdrawal (> 50k)
                new FraudRule { RuleId = 2, FieldName = "Amount", Operator = "<", ThresholdValue = "-10000" }, // Medium Withdrawal (> 10k)
                new FraudRule { RuleId = 3, FieldName = "Amount", Operator = ">", ThresholdValue = "100000" }   // Large Deposit (> 100k)
            };

            // Act
            var brokenRuleIds = engine.EvaluateRecord(record, activeRules);

            // Assert
            Assert.Equal(2, brokenRuleIds.Count);
            Assert.Contains(1, brokenRuleIds);
            Assert.Contains(2, brokenRuleIds);
            Assert.DoesNotContain(3, brokenRuleIds);
        }

        #endregion

        #region 2. Security Utilities & Password Hashing Unit Tests

        [Fact]
        public void SecurityUtils_HashPasswordSha256_ProducesConsistentValidHash()
        {
            // Arrange
            string rawPassword = "CapitecSecurePass2026!";

            // Act
            string hash1 = SecurityUtils.HashPasswordSha256(rawPassword);
            string hash2 = SecurityUtils.HashPasswordSha256(rawPassword);

            // Assert
            Assert.NotNull(hash1);
            Assert.NotEmpty(hash1);
            Assert.Equal(64, hash1.Length);
            Assert.Equal(hash1, hash2);
        }

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        public void SecurityUtils_HashPasswordSha256_HandlesEmptyOrWhitespaceInput(string input)
        {
            // Act
            string hash = SecurityUtils.HashPasswordSha256(input);

            // Assert
            Assert.NotNull(hash);
            Assert.NotEmpty(hash);
        }

        #endregion

        #region 3. Integration & Dummy File Ingestion Tests

        [Fact]
        public void DummyDataGenerator_GeneratesValidCsvFile_WithExpectedHeaderAndFormat()
        {
            // Arrange
            string tempDir = CreateTempTestDirectory();

            // Act
            string filePath = DummyFileGenerator.Generate(tempDir);

            // Assert
            Assert.True(File.Exists(filePath));
            var lines = File.ReadAllLines(filePath);
            Assert.True(lines.Length > 1, "CSV file must contain a header and at least one data record.");

            string header = lines[0];
            Assert.Contains("TransactionId", header);
            Assert.Contains("AccountNumber", header);
            Assert.Contains("Amount", header);
            Assert.Contains("TransactionType", header);
        }

        [Fact]
        public void DummyDataGenerator_DoesNotTriggerDirectionalMismatchAlerts()
        {
            // Arrange
            string tempDir = CreateTempTestDirectory();
            string generatedCsvPath = DummyFileGenerator.Generate(tempDir);

            // Parse generated CSV into TransactionRecord models
            var records = ParseCsvToTransactionRecords(generatedCsvPath);
            Assert.NotEmpty(records);

            var activeRules = new List<FraudRule>
            {
                new FraudRule { RuleId = 1, FieldName = "Amount", Operator = "<", ThresholdValue = "-50000" }, // High Withdrawal
                new FraudRule { RuleId = 6, FieldName = "Amount", Operator = "<", ThresholdValue = "-2000" }   // Over 2k Outbound
            };

            var engine = new FraudEvaluationEngine(new IFraudRuleEvaluator[] { _numericEvaluator });

            // Act
            var brokenAlerts = new List<(TransactionRecord Record, int RuleId)>();
            foreach (var record in records)
            {
                var brokenRuleIds = engine.EvaluateRecord(record, activeRules);
                foreach (var ruleId in brokenRuleIds)
                {
                    brokenAlerts.Add((record, ruleId));
                }
            }

            // Assert: Direction Guard Check
            bool hasInvalidDepositAlerts = brokenAlerts.Any(alert =>
                alert.Record.Amount > 0 &&
                activeRules.Any(r => r.RuleId == alert.RuleId && decimal.Parse(r.ThresholdValue) < 0));

            Assert.False(hasInvalidDepositAlerts, "Deposits (> 0) should never trigger negative threshold (< 0) rules.");
        }

        #endregion

        #region Helper Methods

        private static List<TransactionRecord> ParseCsvToTransactionRecords(string filePath)
        {
            var records = new List<TransactionRecord>();
            var lines = File.ReadAllLines(filePath);

            foreach (var line in lines.Skip(1))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;

                var parts = line.Split(',');
                if (parts.Length < 7) continue;

                records.Add(new TransactionRecord
                {
                    TransactionId = parts[0],
                    AccountNumber = parts[1],
                    AccountName = parts[2],
                    TransactionDate = DateTime.Parse(parts[3], CultureInfo.InvariantCulture),
                    Amount = decimal.Parse(parts[4], CultureInfo.InvariantCulture),
                    TransactionType = TransactionTypeConstants.FromString(parts[5]),
                    Merchant = parts[6]
                });
            }

            return records;
        }

        #endregion
    }
}