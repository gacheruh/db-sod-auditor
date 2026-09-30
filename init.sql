-- Create sample roles and users with intentional SoD violations for testing
CREATE ROLE finance_clerk;
CREATE ROLE database_admin;

-- Violation user: Has both finance clerk duties and admin-like table manipulation rights
CREATE USER rogue_employee WITH PASSWORD 'password123';
GRANT finance_clerk TO rogue_employee;
GRANT database_admin TO rogue_employee;

-- Compliant user: Standard read-only auditor
CREATE USER safe_auditor WITH PASSWORD 'password123';

-- Create a sensitive financial table
CREATE TABLE financial_transactions (
    transaction_id SERIAL PRIMARY KEY,
    amount NUMERIC,
    status VARCHAR(50)
);

-- Grant conflicting permissions to the rogue user directly
GRANT SELECT, INSERT, DELETE, DROP ON financial_transactions TO rogue_employee;
GRANT SELECT ON financial_transactions TO safe_auditor;
