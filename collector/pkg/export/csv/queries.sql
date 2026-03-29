-- rbscope DuckDB Queries
-- Usage: duckdb -c ".read queries.sql" (from the CSV output directory)
-- Or:    duckdb <<< "SELECT ... FROM read_csv_auto('rbscope_samples.csv') ..."

-- Top Ruby methods by sample count (CPU time proxy)
SELECT leaf_method, SUM(weight) as samples
FROM read_csv_auto('rbscope_samples.csv')
WHERE leaf_method != ''
GROUP BY 1 ORDER BY 2 DESC LIMIT 20;

-- I/O latency by connection target
SELECT connection, syscall,
       COUNT(*) as count,
       AVG(latency_ns)/1e6 as avg_ms,
       PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY latency_ns)/1e6 as p99_ms,
       SUM(bytes) as total_bytes
FROM read_csv_auto('rbscope_io.csv')
WHERE connection != ''
GROUP BY 1, 2 ORDER BY avg_ms DESC;

-- Off-CPU time by reason
SELECT reason,
       COUNT(*) as events,
       SUM(off_cpu_ns)/1e6 as total_ms,
       AVG(off_cpu_ns)/1e6 as avg_ms
FROM read_csv_auto('rbscope_sched.csv')
GROUP BY 1 ORDER BY total_ms DESC;

-- Thread activity summary
SELECT tid,
       COUNT(*) as samples,
       SUM(weight) as weighted_samples
FROM read_csv_auto('rbscope_samples.csv')
GROUP BY 1 ORDER BY 2 DESC;

-- Slowest individual I/O operations
SELECT timestamp_ns, tid, syscall, connection,
       latency_ns/1e6 as latency_ms, bytes
FROM read_csv_auto('rbscope_io.csv')
ORDER BY latency_ns DESC LIMIT 20;

-- Full stack traces for a specific method
SELECT full_stack, COUNT(*) as samples
FROM read_csv_auto('rbscope_samples.csv')
WHERE leaf_method LIKE '%Controller%'
GROUP BY 1 ORDER BY 2 DESC LIMIT 10;
