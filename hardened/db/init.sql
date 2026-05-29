-- Demo database schema (educational only)
CREATE TABLE IF NOT EXISTS demo_users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50),
    role VARCHAR(20) DEFAULT 'user'
);

INSERT INTO demo_users (username, role) VALUES ('demo_user', 'user');
