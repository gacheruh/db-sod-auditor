# Automated Database User Privilege & Segregation of Duties (SoD) Auditor

This project demonstrates an entry-level Information Systems auditing tool that connects to a PostgreSQL database, analyzes user privileges from system catalogs, and flags Segregation of Duties (SoD) violations (such as users possessing both data entry and destructive deletion rights on the same table).

## Project Structure
- `docker-compose.yml`: Spins up a local PostgreSQL instance.
- `init.sql`: Sets up test users, roles, tables, and intentional SoD violations.
- `requirements.txt`: Python package dependencies (`psycopg2-binary`, `tabulate`).
- `audit.py`: The core audit script that inspects privileges and evaluates rules.

## Quick Start
1. **Start the Database:**
   ```bash
   docker compose up -d
   ```
2. **Install Python Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
3. **Run the Auditor:**
   ```bash
   python audit.py
   ```
