# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2025-02-24

### Security
- Fixed metadata queries in multi-database environments to restrict access to current database schema only

### Code Quality
- Extracted table structure query into `COLUMN_METADATA_QUERY` constant
- Standardized use of `DATABASE()` function to ensure proper query scope
- Unified implementation of all table structure related queries

### Fixed
- Resolved an issue where table structures from other databases could be queried in multi-database environments

## [0.1.0] - 2025-02-20

### Added
- Initial release
- Basic MySQL MCP server implementation
- Support for read-only SELECT queries
- Database structure viewing capabilities
- Transaction support for data modifications
- Security checks and query limitations
- Performance monitoring and logging 