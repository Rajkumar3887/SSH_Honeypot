-- ════════════════════════════════════════════════════════════════════════════
-- sample-queries.sql
-- Useful SQLite queries for SSH Honeypot analysis and reporting
-- Usage: sqlite3 honeypot.db < sample-queries.sql
--        sqlite3 honeypot.db "SELECT ..."
-- ════════════════════════════════════════════════════════════════════════════


-- ── TOP ATTACKERS ────────────────────────────────────────────────────────────

-- Top 10 IPs by total auth attempts
SELECT source_ip,
       COUNT(*) AS total_attempts,
       SUM(success) AS successful,
       COUNT(*) - SUM(success) AS failed
FROM auth_attempts
GROUP BY source_ip
ORDER BY total_attempts DESC
LIMIT 10;


-- Top 10 IPs by command count (most active attackers post-auth)
SELECT source_ip, COUNT(*) AS command_count
FROM commands
GROUP BY source_ip
ORDER BY command_count DESC
LIMIT 10;


-- ── MOST USED COMMANDS ───────────────────────────────────────────────────────

-- Top 20 commands across all sessions
SELECT command, COUNT(*) AS cnt
FROM commands
GROUP BY command
ORDER BY cnt DESC
LIMIT 20;


-- Commands run by a specific attacker
-- Replace '1.2.3.4' with the attacker's IP
SELECT command, issued_at
FROM commands
WHERE source_ip = '1.2.3.4'
ORDER BY issued_at ASC;


-- ── THREAT ANALYSIS ─────────────────────────────────────────────────────────

-- Threat count by severity
SELECT severity, COUNT(*) AS count
FROM threats
GROUP BY severity
ORDER BY
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high'     THEN 2
        WHEN 'medium'   THEN 3
        WHEN 'low'      THEN 4
        ELSE 5
    END;


-- Threat count by MITRE ATT&CK category
SELECT category, COUNT(*) AS count
FROM threats
GROUP BY category
ORDER BY count DESC;


-- Recent high-priority threats (last 24 hours)
SELECT source_ip, category, severity, command, message, detected_at
FROM threats
WHERE severity IN ('critical', 'high')
  AND detected_at >= datetime('now', '-24 hours')
ORDER BY detected_at DESC
LIMIT 50;


-- Sessions with privilege escalation attempts
SELECT DISTINCT source_ip, command, issued_at
FROM commands
WHERE command LIKE '%su%'
   OR command LIKE '%sudo%'
   OR command LIKE '%chmod%'
ORDER BY issued_at DESC;


-- ── CREDENTIAL ANALYSIS ─────────────────────────────────────────────────────

-- Most attempted usernames
SELECT username, COUNT(*) AS attempts
FROM auth_attempts
GROUP BY username
ORDER BY attempts DESC
LIMIT 20;


-- Credential stuffing detection (same password hash tried from multiple IPs)
SELECT password, COUNT(DISTINCT source_ip) AS unique_ips, COUNT(*) AS total_attempts
FROM auth_attempts
GROUP BY password
HAVING unique_ips > 2
ORDER BY unique_ips DESC;


-- ── SESSION TIMELINE ─────────────────────────────────────────────────────────

-- Full session timeline for a specific IP (forensic view)
-- Replace '1.2.3.4' with the attacker's IP
SELECT 'AUTH' AS event_type, username AS detail, attempted_at AS ts
FROM auth_attempts WHERE source_ip = '1.2.3.4'
UNION ALL
SELECT 'CMD', command, issued_at
FROM commands WHERE source_ip = '1.2.3.4'
UNION ALL
SELECT 'THREAT', category || ': ' || message, detected_at
FROM threats WHERE source_ip = '1.2.3.4'
ORDER BY ts ASC;


-- ── SENSITIVE FILE ACCESS ────────────────────────────────────────────────────

-- Which files were accessed most
SELECT file_path, COUNT(*) AS access_count, COUNT(DISTINCT source_ip) AS unique_ips
FROM file_access
GROUP BY file_path
ORDER BY access_count DESC;


-- Attackers who accessed sensitive lure files
SELECT source_ip, username, file_path, accessed_at
FROM file_access
WHERE file_path IN ('/home/corpuser/secret.txt', '/etc/shadow', '/root/.ssh/id_rsa')
ORDER BY accessed_at DESC;


-- ── STATISTICS & REPORTING ───────────────────────────────────────────────────

-- Daily attack statistics (last 30 days)
SELECT date(connected_at) AS day,
       COUNT(*) AS connections
FROM connections
WHERE connected_at >= datetime('now', '-30 days')
GROUP BY day
ORDER BY day;


-- Hourly attack pattern (to detect scheduled attacks)
SELECT strftime('%H', connected_at) AS hour,
       COUNT(*) AS connections
FROM connections
GROUP BY hour
ORDER BY hour;


-- Session duration statistics
SELECT source_ip,
       connected_at,
       disconnected_at,
       ROUND((julianday(disconnected_at) - julianday(connected_at)) * 86400) AS duration_seconds
FROM connections
WHERE disconnected_at IS NOT NULL
ORDER BY duration_seconds DESC
LIMIT 20;


-- ── DATA EXPORT ─────────────────────────────────────────────────────────────

-- Export all threats to CSV (run from command line):
-- sqlite3 -header -csv honeypot.db "SELECT * FROM threats ORDER BY detected_at;" > threats_export.csv

-- Export commands to CSV:
-- sqlite3 -header -csv honeypot.db "SELECT * FROM commands ORDER BY issued_at;" > commands_export.csv

-- ── DATABASE HEALTH ──────────────────────────────────────────────────────────

-- Row counts for all tables
SELECT 'connections'   AS table_name, COUNT(*) AS rows FROM connections
UNION ALL
SELECT 'auth_attempts', COUNT(*) FROM auth_attempts
UNION ALL
SELECT 'commands',      COUNT(*) FROM commands
UNION ALL
SELECT 'threats',       COUNT(*) FROM threats
UNION ALL
SELECT 'file_access',   COUNT(*) FROM file_access;


-- Database file size (run from sqlite3 prompt with .dbinfo)
-- .dbinfo
