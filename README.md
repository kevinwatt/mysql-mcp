# MySQL MCP Server

An MCP server implementation that integrates with MySQL databases, providing secure database access capabilities for LLMs.

## Features

* **Read Operations**
  * Execute read-only SELECT queries
  * List all database tables
  * Show table structures
  * View schema information
* **Write Operations**
  * Execute INSERT/UPDATE/DELETE with transaction support
  * Parameterized queries for data safety
  * Returns affected rows and insert IDs
* **Security**
  * Read-only transaction mode for SELECT queries
  * Query length and result size limits
  * Performance monitoring and logging
  * Automatic transaction handling

## Installation

```bash
npm install -g github:gemini-dk/mysql-mcp-server
```

## Usage with [Dive Desktop](https://github.com/OpenAgentPlatform/Dive)

1. Click "+ Add MCP Server" in Dive Desktop
2. Copy and paste this configuration:

```json
{
  "mcpServers": {
    "mysql": {
      "command": "npx",
      "args": [
        "-y",
        "github:gemini-dk/mysql-mcp-server"
      ],
      "env": {
        "MYSQL_HOST": "127.0.0.1",
        "MYSQL_PORT": "3306",
        "MYSQL_USER": "root",
        "MYSQL_PASS": "",
        "MYSQL_DB": "your_database"
      }
    }
  }
}
```

3. Click "Save" to install the MCP server

## Tool Documentation

* **mysql_query**
  * Execute read-only SELECT queries
  * Inputs:
    * `sql` (string): SQL SELECT query to execute
  * Limits:
    * Maximum query length: 4096 characters
    * Maximum result rows: 1000
    * Query timeout: 30 seconds

* **mysql_execute**
  * Execute data modification operations
  * Inputs:
    * `sql` (string): SQL statement (INSERT/UPDATE/DELETE)
    * `params` (array, optional): Parameters for the SQL statement
  * Features:
    * Returns affected rows count
    * Returns last insert ID
    * Automatic transaction handling

* **list_tables**
  * List all tables in current database
  * No inputs required

* **describe_table**
  * Show table structure
  * Inputs:
    * `table` (string): Table name to describe

## Usage Examples

Ask your LLM to:

```
"Show me all tables in the database"
"Describe the structure of users table"
"Select all active users from the database"
"Insert a new record into orders table"
```

## Manual Start

If needed, start the server manually:

```bash
npx @kevinwatt/mysql-mcp
```

## Requirements

* Node.js 18+
* MySQL Server
* MCP-compatible LLM service

## License

MIT

## Author

Dewei Yen

## Keywords

* mcp
* mysql
* database
* dive
* llm
* ai
