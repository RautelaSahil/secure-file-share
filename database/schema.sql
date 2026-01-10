-- DATABASE
CREATE DATABASE IF NOT EXISTS secure_file_share;
USE secure_file_share;

-- =========================
-- USERS
-- =========================
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,

    -- Display username (case-preserved)
    username VARCHAR(50) NOT NULL,

    -- Normalized username (used for login & uniqueness)
    username_normalized VARCHAR(50) COLLATE utf8mb4_bin NOT NULL UNIQUE,

    -- Secure password hash
    password_hash VARCHAR(255) NOT NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (username)
);

-- =========================
-- FILES (OWNERSHIP)
-- =========================
CREATE TABLE files (
    id INT AUTO_INCREMENT PRIMARY KEY,
    owner_id INT NOT NULL,

    original_filename VARCHAR(255) NOT NULL,
    stored_filename VARCHAR(255) NOT NULL,

    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (owner_id)
        REFERENCES users(id)
        ON DELETE CASCADE
);

-- Index for fast ownership checks
CREATE INDEX idx_files_owner
ON files (owner_id);

-- =========================
-- FILE SHARES
-- =========================
CREATE TABLE file_shares (
    id INT AUTO_INCREMENT PRIMARY KEY,

    file_id INT NOT NULL,
    shared_with_user_id INT NOT NULL,

    -- NULL = never expires
    expires_at TIMESTAMP NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Prevent duplicate sharing
    UNIQUE (file_id, shared_with_user_id),

    FOREIGN KEY (file_id)
        REFERENCES files(id)
        ON DELETE CASCADE,

    FOREIGN KEY (shared_with_user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
);

-- Index for "Shared With Me" queries
CREATE INDEX idx_file_shares_user
ON file_shares (shared_with_user_id);

-- =========================
-- AUDIT LOGS
-- =========================
CREATE TABLE audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,

    user_id INT NULL,
    file_id INT NULL,

    action VARCHAR(50) NOT NULL,
    success BOOLEAN NOT NULL,
    ip_address VARCHAR(45),

    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE SET NULL,

    FOREIGN KEY (file_id)
        REFERENCES files(id)
        ON DELETE SET NULL
);

-- Indexes for audit review
CREATE INDEX idx_audit_user
ON audit_logs (user_id);

CREATE INDEX idx_audit_file
ON audit_logs (file_id);
