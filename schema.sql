CREATE DATABASE IF NOT EXISTS mfg_network_diagnostics;
USE mfg_network_diagnostics;

CREATE TABLE IF NOT EXISTS ip_logs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_agent VARCHAR(1000) NOT NULL DEFAULT '',
    endpoint VARCHAR(255) NOT NULL DEFAULT '',
    INDEX idx_ip (ip_address),
    INDEX idx_timestamp (timestamp)
);
