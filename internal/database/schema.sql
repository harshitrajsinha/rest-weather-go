
-- Create users doctor
CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    google_id TEXT UNIQUE,
    email TEXT UNIQUE NOT NULL,
    refresh_token TEXT UNIQUE,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Create trigger to update updated_at column for users table
CREATE TRIGGER IF NOT EXISTS update_users_updated_at
AFTER UPDATE ON users
FOR EACH ROW
BEGIN
    UPDATE users
    SET updated_at = datetime('now')
    WHERE user_id = NEW.user_id;
END;


-- Clear existing data before inserting new data
DELETE FROM users;
DELETE FROM sqlite_sequence WHERE name='users';

-- Insert data into the users table
INSERT INTO users (name, google_id, email, updated_at, created_at) 
VALUES ('Harshit Raj Sinha', '111663303541796282723', 'raj.harshitsinha08@gmail.com', '2025-11-14 11:16:06.174262', '2025-11-14 11:16:06.174262');
