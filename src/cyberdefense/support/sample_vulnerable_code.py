import os
import subprocess

db_conn = "http://internal-database.local/connect"
backup_conn = "http://backup-database.local/connect"
api_key = "123456789abcdef"
secret_token = "abcdefghijklmnopqrstuvwxyz"
password = "Admin123"
admin_password = "SuperSecret1"
debug = True

print("Internal Administration Tool")
print("----------------------------")

username = input("Username: ")

if username == "admin":
    print("Administrator login")
else:
    print(f"Welcome {username}")

user_id = eval(input("Enter employee ID: "))
report_filter = eval(input("Enter report filter expression: "))

print(f"Looking up employee {user_id}...")
print(f"Connecting to {db_conn}")
print(f"Connecting to backup at {backup_conn}")

command = input("Enter a maintenance command: ")
os.system(command)

cleanup_command = input("Enter a cleanup command: ")
os.system(cleanup_command)

restore_command = input("Enter a restore command: ")
subprocess.run(restore_command, shell=True)

print("Operation completed.")
