import mysql.connector
from mysql.connector import Error
import logging
import os
from datetime import datetime, timedelta
import csv
import schedule
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Log file paths
log_file_path = "/var/log/sigmaueba/anomaly.csv"
archive_path = "/var/log/sigmaueba/anomaly_archive.csv"

# Database configuration
db_config = {
    "host": "localhost",
    "user": "sigma",
    "password": "sigma",
    "database": "sigma_db",
}

# Helper functions
def fetch_anomalies():
    """Fetch anomalies (cluster -1) from the sigma_alerts table."""
    try:
        connection = mysql.connector.connect(**db_config)
        with connection.cursor() as cursor:
            select_query = """
            SELECT system_time, provider_name, title, tags, description, computer_name, user_id, event_id
            FROM sigma_alerts
            WHERE dbscan_cluster = -1
            """
            cursor.execute(select_query)
            anomalies = cursor.fetchall()
        return anomalies
    except Error as e:
        logging.error(f"Error fetching anomalies: {e}")
        return []
    finally:
        if connection.is_connected():
            connection.close()

def load_logged_anomalies():
    """Load anomalies from the log file."""
    if not os.path.exists(log_file_path):
        return {}

    logged_anomalies = {}
    with open(log_file_path, "r") as log_file:
        csv_reader = csv.reader(log_file)
        next(csv_reader)  # Skip header
        for row in csv_reader:
            system_time = row[0]
            provider_name = row[1]
            last_seen = datetime.strptime(system_time, "%Y-%m-%d %H:%M:%S")
            logged_anomalies[(system_time, provider_name)] = last_seen
    return logged_anomalies

def save_logged_anomalies(anomalies):
    """Write anomalies to the log file with newer logs first."""
    headers = ["system_time", "provider_name", "title", "tags", "description", "computer_name", "user_id", "event_id"]

    existing_logs = []
    if os.path.exists(log_file_path):
        with open(log_file_path, "r") as log_file:
            csv_reader = csv.reader(log_file)
            existing_headers = next(csv_reader)  # Read header
            existing_logs = list(csv_reader)

    all_logs = anomalies + existing_logs
    # Ensure all system_time entries are strings
    all_logs = [[str(item) if isinstance(item, datetime) else item for item in log] for log in all_logs]
    # Sort logs by system_time in descending order
    all_logs.sort(key=lambda x: datetime.strptime(x[0], '%Y-%m-%d %H:%M:%S'), reverse=True)

    with open(log_file_path, "w", newline='') as log_file:
        csv_writer = csv.writer(log_file)
        csv_writer.writerow(headers)
        csv_writer.writerows(all_logs)

def archive_old_anomalies():
    """Archive anomalies older than 7 days."""
    if not os.path.exists(log_file_path):
        return

    cutoff_date = datetime.now() - timedelta(days=7)
    anomalies_to_keep = []
    anomalies_to_archive = []

    with open(log_file_path, "r") as log_file:
        csv_reader = csv.reader(log_file)
        headers = next(csv_reader)  # Read header
        for row in csv_reader:
            system_time = datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S")
            if system_time < cutoff_date:
                anomalies_to_archive.append(row)
            else:
                anomalies_to_keep.append(row)

    # Save the remaining anomalies back to the log file
    with open(log_file_path, "w", newline='') as log_file:
        csv_writer = csv.writer(log_file)
        csv_writer.writerow(headers)
        csv_writer.writerows(anomalies_to_keep)

    # Append the archived anomalies to the archive file
    if anomalies_to_archive:
        archive_exists = os.path.exists(archive_path)
        with open(archive_path, "a", newline='') as archive_file:
            csv_writer = csv.writer(archive_file)
            if not archive_exists:
                csv_writer.writerow(headers)  # Write header if archive file is new
            csv_writer.writerows(anomalies_to_archive)

def log_anomalies(anomalies, logged_anomalies):
    """Log new anomalies to the log file if they haven't been logged within the last hour."""
    now = datetime.now()
    new_logs = []

    for anomaly in anomalies:
        system_time = anomaly[0].strftime('%Y-%m-%d %H:%M:%S')
        provider_name = anomaly[1]
        if (system_time, provider_name) in logged_anomalies and now - logged_anomalies[(system_time, provider_name)] <= timedelta(hours=1):
            continue

        logged_anomalies[(system_time, provider_name)] = now
        new_logs.append([system_time] + list(anomaly[1:]))  # Ensure system_time is a string
        logging.info(f"Logged anomaly: {system_time} from {provider_name}")

    if new_logs:
        save_logged_anomalies(new_logs)

def detect_and_log_anomalies():
    """Detect anomalies and log them."""
    logged_anomalies = load_logged_anomalies()
    anomalies = fetch_anomalies()
    log_anomalies(anomalies, logged_anomalies)
    archive_old_anomalies()  # Archive old anomalies

# Run the script immediately with existing data
detect_and_log_anomalies()

# Schedule anomaly detection and logging every 5 minutes
schedule.every(5).minutes.do(detect_and_log_anomalies)

while True:
    schedule.run_pending()
    time.sleep(1)
