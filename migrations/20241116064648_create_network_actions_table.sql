-- Add migration script here
CREATE TABLE network_actions (
    id SERIAL PRIMARY KEY,
    action VARCHAR(50) NOT NULL,
    performed_by VARCHAR(100) NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
