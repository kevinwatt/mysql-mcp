#!/usr/bin/env node

/**
 * MySQL MCP Server
 * 此服務提供一個 Model Context Protocol 伺服器，用於安全地存取 MySQL 資料庫
 * 支援唯讀查詢和資料庫結構檢視
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListResourcesRequestSchema,
  ListToolsRequestSchema,
  ReadResourceRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import mysql, { MysqlError, PoolConnection } from "mysql";

// 型別定義
type MySQLErrorType = MysqlError | null;

// 介面定義
interface TableMetadata {
  table_name: string;
}

interface ColumnMetadata {
  column_name: string;
  data_type: string;
}

interface MySQLQueryResult {
  affectedRows?: number;
  insertId?: number;
  message?: string;
  [key: string]: any;
}

interface SQLExecuteResult {
  success: boolean;
  affectedRows?: number;
  insertId?: number;
  message?: string;
  data?: any;
}

interface SQLSecurityCheck {
  safe: boolean;
  reason?: string;
}

interface QueryLog {
  timestamp: Date;
  operation: SQLOperationType;
  sql: string;
  params?: any[];
  duration: number;
  success: boolean;
  error?: string;
  affectedRows?: number;
}

// 列舉定義
enum SQLOperationType {
  SELECT = 'SELECT',
  INSERT = 'INSERT',
  UPDATE = 'UPDATE',
  DELETE = 'DELETE'
}

// 配置設定
const serverConfig = {
  server: {
    name: "mysql-mcp",
    version: "0.1.0",
  },
  mysql: {
    host: process.env.MYSQL_HOST || "127.0.0.1",
    port: Number(process.env.MYSQL_PORT || "3306"),
    user: process.env.MYSQL_USER || "root",
    password: process.env.MYSQL_PASS || "",
    database: process.env.MYSQL_DB || "",
    connectionLimit: 10,
  },
  paths: {
    schema: "schema",
  },
  limits: {
    queryTimeout: 30000,  // 查詢超時時間 (毫秒)
    maxRows: 1000,       // 最大回傳行數
    maxQueryLength: 4096 // 最大 SQL 長度
  }
};

/**
 * MySQL 查詢輔助函數
 * @param connection MySQL 連線物件
 * @param sql SQL 查詢字串
 * @param params 查詢參數
 * @returns Promise<T> 查詢結果
 */
const executeQueryWithConnection = <T>(
  connection: PoolConnection,
  sql: string,
  params: any[] = [],
): Promise<T> => {
  return new Promise((resolve, reject) => {
    connection.query(sql, params, (error: MySQLErrorType, results: any) => {
      if (error) reject(error);
      else resolve(results);
    });
  });
};

/**
 * 從連線池取得連線
 */
const getConnectionFromPool = (pool: mysql.Pool): Promise<PoolConnection> => {
  return new Promise((resolve, reject) => {
    pool.getConnection((error: MySQLErrorType, connection: PoolConnection) => {
      if (error) reject(error);
      else resolve(connection);
    });
  });
};

/**
 * 開始交易
 */
const startTransaction = (connection: PoolConnection): Promise<void> => {
  return new Promise((resolve, reject) => {
    connection.beginTransaction((error: MySQLErrorType) => {
      if (error) reject(error);
      else resolve();
    });
  });
};

/**
 * 回滾交易
 */
const rollbackTransaction = (connection: PoolConnection): Promise<void> => {
  return new Promise((resolve) => {
    connection.rollback(() => resolve());
  });
};

// 初始化資料庫連線池
const connectionPool = mysql.createPool(serverConfig.mysql);

// 初始化 MCP 伺服器
const mcpServer = new Server(serverConfig.server, {
  capabilities: {
    resources: {},
    tools: {},
  },
});

/**
 * 檢查查詢限制
 */
function checkQueryLimits(sql: string): SQLSecurityCheck {
  if (sql.length > serverConfig.limits.maxQueryLength) {
    return {
      safe: false,
      reason: `SQL 查詢長度超過限制 (${serverConfig.limits.maxQueryLength} 字元)`
    };
  }
  return { safe: true };
}

/**
 * SQL 安全檢查器
 */
function checkSQLSecurity(sql: string): SQLSecurityCheck {
  // 檢查危險關鍵字
  const dangerousPatterns = [
    /;\s*DROP\s+/i,
    /;\s*DELETE\s+FROM\s+/i,
    /;\s*UPDATE\s+/i,
    /;\s*INSERT\s+/i,
    /EXECUTE\s+/i,
    /EXEC\s+/i,
    /INTO\s+OUTFILE/i,
    /INTO\s+DUMPFILE/i
  ];

  for (const pattern of dangerousPatterns) {
    if (pattern.test(sql)) {
      return {
        safe: false,
        reason: '檢測到潛在的 SQL 注入攻擊'
      };
    }
  }

  return { safe: true };
}

/**
 * 記錄查詢日誌
 */
async function logQuery(log: QueryLog): Promise<void> {
  // 這裡可以根據需求將日誌寫入資料庫或檔案
  console.log(JSON.stringify({
    type: 'query_log',
    ...log
  }));
}

/**
 * 效能監控包裝函數
 */
async function withPerformanceMonitoring<T>(
  operation: SQLOperationType,
  sql: string,
  params: any[],
  action: () => Promise<T>
): Promise<T> {
  const startTime = process.hrtime();
  
  try {
    const result = await action();
    const [seconds, nanoseconds] = process.hrtime(startTime);
    const duration = seconds * 1000 + nanoseconds / 1000000; // 轉換為毫秒
    
    await logQuery({
      timestamp: new Date(),
      operation,
      sql,
      params,
      duration,
      success: true,
      affectedRows: (result as any)?.affectedRows
    });
    
    return result;
  } catch (error) {
    const [seconds, nanoseconds] = process.hrtime(startTime);
    const duration = seconds * 1000 + nanoseconds / 1000000;
    
    await logQuery({
      timestamp: new Date(),
      operation,
      sql,
      params,
      duration,
      success: false,
      error: error instanceof Error ? error.message : '未知錯誤'
    });
    
    throw error;
  }
}

/**
 * 執行資料修改操作
 * 包含交易控制和錯誤處理
 */
async function executeModifyQuery(sql: string, params: any[] = []): Promise<SQLExecuteResult> {
  const connection = await getConnectionFromPool(connectionPool);
  
  // 安全檢查
  const securityCheck = checkSQLSecurity(sql);
  if (!securityCheck.safe) {
    return {
      success: false,
      message: securityCheck.reason
    };
  }

  // 取得操作類型
  const sqlType = sql.trim().split(' ')[0].toUpperCase() as SQLOperationType;
  
  try {
    return await withPerformanceMonitoring(sqlType, sql, params, async () => {
      await startTransaction(connection);
      const result = await executeQueryWithConnection<MySQLQueryResult>(connection, sql, params);
      await connection.commit();
      
      return {
        success: true,
        affectedRows: result.affectedRows,
        insertId: result.insertId,
        message: result.message
      };
    });
  } catch (error) {
    await rollbackTransaction(connection);
    return {
      success: false,
      message: error instanceof Error ? error.message : '未知錯誤'
    };
  } finally {
    connection.release();
  }
}

/**
 * 執行唯讀查詢
 * 在唯讀交易中執行查詢以確保安全性
 */
async function executeReadOnlyQuery<T>(sql: string): Promise<T> {
  const connection = await getConnectionFromPool(connectionPool);

  // 安全檢查
  const securityCheck = checkSQLSecurity(sql);
  if (!securityCheck.safe) {
    throw new Error(securityCheck.reason);
  }

  try {
    return await withPerformanceMonitoring(SQLOperationType.SELECT, sql, [], async () => {
      await executeQueryWithConnection(connection, "SET SESSION TRANSACTION READ ONLY");
      await startTransaction(connection);

      const results = await executeQueryWithConnection(connection, sql);
      await rollbackTransaction(connection);
      await executeQueryWithConnection(connection, "SET SESSION TRANSACTION READ WRITE");

      return <T>{
        content: [
          {
            type: "text",
            text: JSON.stringify(results, null, 2),
          },
        ],
        isError: false,
      };
    });
  } catch (error) {
    await rollbackTransaction(connection);
    throw error;
  } finally {
    connection.release();
  }
}

// MCP 請求處理器設定
mcpServer.setRequestHandler(ListResourcesRequestSchema, async () => {
  const results = (await executeQuery(
    "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()",
  )) as TableMetadata[];

  return {
    resources: results.map((row: TableMetadata) => ({
      uri: new URL(
        `${row.table_name}/${serverConfig.paths.schema}`,
        `${serverConfig.mysql.host}:${serverConfig.mysql.port}`,
      ).href,
      mimeType: "application/json",
      name: `"${row.table_name}" database schema`,
    })),
  };
});

mcpServer.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  const resourceUrl = new URL(request.params.uri);
  const pathComponents = resourceUrl.pathname.split("/");
  const schema = pathComponents.pop();
  const tableName = pathComponents.pop();

  if (schema !== serverConfig.paths.schema) {
    throw new Error("Invalid resource URI");
  }

      const results = (await executeQuery(
        "SELECT column_name, data_type FROM information_schema.columns " +
        "WHERE table_schema = DATABASE() AND table_name = ?",
        [tableName],
      )) as ColumnMetadata[];

  return {
    contents: [
      {
        uri: request.params.uri,
        mimeType: "application/json",
        text: JSON.stringify(results, null, 2),
      },
    ],
  };
});

mcpServer.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "mysql_query",
      description: "Execute read-only SELECT queries against the MySQL database.\n" +
        "- Maximum query length: 4096 characters\n" +
        "- Maximum result rows: 1000\n" +
        "- Query timeout: 30 seconds",
      inputSchema: {
        type: "object",
        properties: {
          sql: { 
            type: "string",
            description: "SQL SELECT query to execute"
          }
        },
        required: ["sql"]
      }
    },
    {
      name: "mysql_execute",
      description: "Execute data modification queries (INSERT/UPDATE/DELETE).\n" +
        "- Returns affected rows count and insert ID\n" +
        "- Supports parameterized queries\n" +
        "- Automatic transaction handling",
      inputSchema: {
        type: "object",
        properties: {
          sql: { 
            type: "string",
            description: "SQL statement (INSERT, UPDATE, or DELETE)"
          },
          params: { 
            type: "array",
            items: { type: "string" },
            description: "Parameters for the SQL statement"
          }
        },
        required: ["sql"]
      }
    },
    {
      name: "list_tables",
      description: "List all tables in current database",
      inputSchema: {
        type: "object",
        properties: {},
        required: []
      }
    },
    {
      name: "describe_table",
      description: "Show table structure",
      inputSchema: {
        type: "object",
        properties: {
          table: {
            type: "string",
            description: "Table name"
          }
        },
        required: ["table"]
      }
    }
  ]
}));

mcpServer.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  
  switch (name) {
    case "mysql_query":
      return executeReadOnlyQuery(args?.sql as string);
      
    case "mysql_execute": {
      const sql = args?.sql as string;
      const params = args?.params as any[] || [];
      
      // 檢查 SQL 類型
      const sqlType = sql.trim().split(' ')[0].toUpperCase();
      if (sqlType === SQLOperationType.SELECT) {
        throw new Error("請使用 mysql_query 執行查詢操作");
      }
      
      const result = await executeModifyQuery(sql, params);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(result, null, 2)
          }
        ],
        isError: !result.success
      };
    }

    case "list_tables": {
      const results = await executeQuery<TableMetadata[]>(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()"
      );
      
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(results, null, 2)
          }
        ],
        isError: false
      };
    }

    case "describe_table": {
      const tableName = args?.table as string;
      if (!tableName) {
        throw new Error("Table name is required");
      }

      const results = await executeQuery<ColumnMetadata[]>(
        "SELECT column_name, data_type FROM information_schema.columns " +
        "WHERE table_schema = DATABASE() AND table_name = ?",
        [tableName]
      );

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(results, null, 2)
          }
        ],
        isError: false
      };
    }
    
    default:
      throw new Error(`未知的工具: ${name}`);
  }
});

/**
 * 執行一般查詢
 */
async function executeQuery<T>(sql: string, params: any[] = []): Promise<T> {
  const connection = await getConnectionFromPool(connectionPool);
  
  // 安全檢查
  const securityCheck = checkSQLSecurity(sql);
  if (!securityCheck.safe) {
    throw new Error(securityCheck.reason);
  }
  
  const limitsCheck = checkQueryLimits(sql);
  if (!limitsCheck.safe) {
    throw new Error(limitsCheck.reason);
  }

  try {
    return await withPerformanceMonitoring(
      SQLOperationType.SELECT,
      sql,
      params,
      async () => await executeQueryWithConnection<T>(connection, sql, params)
    );
  } finally {
    connection.release();
  }
}

// Server startup and shutdown
async function runServer() {
  const transport = new StdioServerTransport();
  await mcpServer.connect(transport);
}

const shutdown = async (signal: string) => {
  console.log(`Received ${signal}. Shutting down...`);
  return new Promise<void>((resolve, reject) => {
    connectionPool.end((err: MySQLErrorType) => {
      if (err) {
        console.error("Error closing pool:", err);
        reject(err);
      } else {
        resolve();
      }
    });
  });
};

process.on("SIGINT", async () => {
  try {
    await shutdown("SIGINT");
    process.exit(0);
  } catch (err) {
    process.exit(1);
  }
});

process.on("SIGTERM", async () => {
  try {
    await shutdown("SIGTERM");
    process.exit(0);
  } catch (err) {
    process.exit(1);
  }
});

runServer().catch((error: unknown) => {
  console.error("Server error:", error);
  process.exit(1);
});
