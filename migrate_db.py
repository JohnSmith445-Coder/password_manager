import sqlite3
import os

# Path to the database file
db_path = 'instance/passwords.db'

# Check if the database file exists
if not os.path.exists(db_path):
    print(f"Error: Database file '{db_path}' not found.")
    exit(1)

# Connect to the database
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Check if the columns already exist
cursor.execute("PRAGMA table_info(password)")
columns = cursor.fetchall()
column_names = [column[1] for column in columns]

# Add the missing columns if they don't exist
columns_to_add = []
if 'notes' not in column_names:
    columns_to_add.append(("notes", "TEXT"))
if 'url' not in column_names:
    columns_to_add.append(("url", "VARCHAR(255)"))
if 'updated_at' not in column_names:
    columns_to_add.append(("updated_at", "DATETIME"))
if 'logo_url' not in column_names:
    columns_to_add.append(("logo_url", "VARCHAR(255)"))

# Execute ALTER TABLE statements for each missing column
for column_name, column_type in columns_to_add:
    try:
        cursor.execute(f"ALTER TABLE password ADD COLUMN {column_name} {column_type}")
        print(f"Added column '{column_name}' to the 'password' table.")
    except sqlite3.Error as e:
        print(f"Error adding column '{column_name}': {e}")

# If updated_at was added, update it with the current timestamp for all rows
if 'updated_at' in [col[0] for col in columns_to_add]:
    try:
        cursor.execute("UPDATE password SET updated_at = datetime('now') WHERE updated_at IS NULL")
        print("Updated 'updated_at' column for existing rows.")
    except sqlite3.Error as e:
        print(f"Error updating 'updated_at' column: {e}")

# Commit the changes and close the connection
conn.commit()
conn.close()

print("Database migration completed successfully.")