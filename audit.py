import os
import psycopg  
from tabulate import tabulate

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_NAME = os.getenv("DB_NAME", "audit_target_db")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "secretpassword")
DB_PORT = os.getenv("DB_PORT", "5432")

HIDE_SYSTEM_TABLES = os.getenv("HIDE_SYSTEM", "True").lower() in ("true", "1", "yes")


def run_sod_audit():
    try:
        # Changed 'database=' to 'dbname=' to match Psycopg 3 specifications
        conn = psycopg.connect(
            host=DB_HOST,
            dbname=DB_NAME,       # <--- Fixed here!
            user=DB_USER,
            password=DB_PASSWORD,
            port=DB_PORT
        )
        cursor = conn.cursor()
        
        print(" Connected to PostgreSQL database successfully.\n")
        print("=== RUNNING SEGREGATION OF DUTIES (SoD) AUDIT ===\n")

        # Query to find users with high-risk conflicting table privileges (e.g., INSERT + DELETE/DROP)
        query = """
            SELECT 
                grantee AS database_user,
                table_name,
                string_agg(privilege_type, ', ') AS privileges
            FROM information_schema.table_privileges
            WHERE grantee NOT IN ('postgres', 'pg_database_owner')
              AND grantee NOT LIKE 'pg_%'
            GROUP BY grantee, table_name;
        """
        
        cursor.execute(query)
        rows = cursor.fetchall()
        
        audit_findings = []
        for row in rows:
            user, table, privs = row
            priv_list = [p.strip() for p in privs.upper().split(',')]
            
            # Define SoD Rule: User should not have BOTH data insertion and destructive privileges (DELETE/DROP)
            has_insert = 'INSERT' in priv_list
            has_destructive = any(p in priv_list for p in ['DELETE', 'DROP', 'ALTER'])
            
            risk_level = "LOW"
            notes = "Compliant access"
            
            if has_insert and has_destructive:
                risk_level = "HIGH (SoD Violation)"
                notes = "User possesses both data entry and destructive/deletion rights on the same table."

            audit_findings.append([user, table, privs, risk_level, notes])

        headers = ["Database User", "Table", "Granted Privileges", "Risk Level", "Audit Notes"]
        print(tabulate(audit_findings, headers=headers, tablefmt="fancy_grid"))

        cursor.close()
        conn.close()

    except Exception as e:
        print(f"Error connecting to database or running audit: {e}")

if __name__ == "__main__":
    run_sod_audit()
