import mysql.connector
from mysql.connector import Error
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.cluster import DBSCAN
from sklearn.feature_extraction.text import TfidfVectorizer
import numpy as np
import logging
import schedule
import time
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Database configuration
db_config = {
    "host": "localhost",
    "user": "sigma",
    "password": "sigma",
    "database": "sigma_db",
}

def fetch_data():
    """Fetch data from the sigma_alerts table."""
    try:
        connection = mysql.connector.connect(**db_config)
        with connection.cursor() as cursor:
            select_query = """
            SELECT id, title, tags, computer_name, user_id, event_id, provider_name
            FROM sigma_alerts
            """
            cursor.execute(select_query)
            data = cursor.fetchall()
        return data
    except Error as e:
        logging.error(f"Error fetching data: {e}")
        return []
    finally:
        if connection.is_connected():
            connection.close()

def ensure_column_exists():
    """Ensure the dbscan_cluster column exists in the sigma_alerts table."""
    try:
        connection = mysql.connector.connect(**db_config)
        with connection.cursor() as cursor:
            cursor.execute("SHOW COLUMNS FROM sigma_alerts LIKE 'dbscan_cluster'")
            result = cursor.fetchone()
            if not result:
                cursor.execute("ALTER TABLE sigma_alerts ADD COLUMN dbscan_cluster INT")
                connection.commit()
                logging.info("Added 'dbscan_cluster' column to 'sigma_alerts' table.")
    except Error as e:
        logging.error(f"Error ensuring 'dbscan_cluster' column exists: {e}")
    finally:
        if connection.is_connected():
            connection.close()

def preprocess_data(data):
    """Preprocess the data for DBSCAN."""
    titles = [row[1] for row in data]
    tags = [row[2] for row in data]
    computer_names = [row[3] for row in data]
    user_ids = [row[4] for row in data]
    event_ids = [row[5] for row in data]
    provider_names = [row[6] for row in data]

    tfidf_vectorizer = TfidfVectorizer(stop_words="english")
    title_tfidf = tfidf_vectorizer.fit_transform(titles)
    tag_tfidf = tfidf_vectorizer.fit_transform(tags)

    label_encoder = LabelEncoder()
    computer_name_encoded = label_encoder.fit_transform(computer_names)
    user_id_encoded = label_encoder.fit_transform(user_ids)
    event_id_encoded = label_encoder.fit_transform(event_ids)
    provider_name_encoded = label_encoder.fit_transform(provider_names)

    combined_data = np.hstack((
        title_tfidf.toarray(),
        tag_tfidf.toarray(),
        computer_name_encoded.reshape(-1, 1),
        user_id_encoded.reshape(-1, 1),
        event_id_encoded.reshape(-1, 1),
        provider_name_encoded.reshape(-1, 1)
    ))

    return combined_data

def run_dbscan(data):
    """Run DBSCAN clustering on the provided data and return the cluster labels."""
    scaler = StandardScaler()
    data_scaled = scaler.fit_transform(data)
    db = DBSCAN(eps=0.5, min_samples=5).fit(data_scaled)
    return db.labels_

def update_cluster_labels(data, cluster_labels):
    """Update the sigma_alerts table with the cluster labels."""
    try:
        connection = mysql.connector.connect(**db_config)
        with connection.cursor() as cursor:
            update_query = """
            UPDATE sigma_alerts
            SET dbscan_cluster = %s
            WHERE id = %s
            """
            update_data = [(int(cluster_labels[i]), data[i][0]) for i in range(len(data))]
            cursor.executemany(update_query, update_data)
            connection.commit()
            logging.info(f"Updated {len(update_data)} records with cluster labels.")
    except Error as e:
        logging.error(f"Error updating cluster labels: {e}")
    finally:
        if connection.is_connected():
            connection.close()

def detect_anomalies():
    """Fetch data, run DBSCAN, and update the database with cluster labels."""
    ensure_column_exists()

    data = fetch_data()
    if not data:
        logging.warning("No data found in the database.")
        return

    preprocessed_data = preprocess_data(data)
    start_time = datetime.now()
    cluster_labels = run_dbscan(preprocessed_data)
    end_time = datetime.now()
    duration = end_time - start_time
    logging.info(f"DBSCAN clustering completed in {duration.total_seconds()} seconds.")

    update_cluster_labels(data, cluster_labels)

# Run the script immediately with existing data
detect_anomalies()

# Schedule anomaly detection every 5 minutes
schedule.every(5).minutes.do(detect_anomalies)

while True:
    schedule.run_pending()
    time.sleep(1)
