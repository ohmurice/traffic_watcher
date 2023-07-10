import mysql.connector
from scapy.all import sniff, IP
import smtplib
from email.mime.text import MIMEText

# Database connection configuration
connection = mysql.connector.connect(
    host="your_host",
    user="your_user",
    password="your_password",
    database="your_db"
)

#Create the database table if it doesn't exist
create_table_query = """
CREATE TABLE IF NOT EXISTS traffic (
    source_ip VARCHAR(20),
    destination_ip VARCHAR(20),
    packet_count INT,
    PRIMARY KEY (source_ip, destination_ip)
);
"""

cursor = connection.cursor()
cursor.execute(create_table_query)

# Function to store traffic data in the database
def store_traffic_data(packet):
    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        packet_count = 1

        # Check if the record already exists
        select_query = "SELECT * FROM traffic WHERE source_ip = %s AND destination_ip = %s"
        cursor.execute(select_query, (source_ip, destination_ip))
        existing_record = cursor.fetchone()

        if existing_record:
            # Record already exists, handle accordingly (update/skip)
            # Example: Update the packet_count of the existing record
            update_query = "UPDATE traffic SET packet_count = packet_count + 1 WHERE source_ip = %s AND destination_ip = %s"
            cursor.execute(update_query, (source_ip, destination_ip))
            connection.commit()
        else:
            # Record doesn't exist, insert the new record
            insert_query = "INSERT INTO traffic (source_ip, destination_ip, packet_count) VALUES (%s, %s, %s)"
            values = (source_ip, destination_ip, packet_count)
            cursor.execute(insert_query, values)
            connection.commit()

        # Perform further processing or analysis as needed


        # Perform anomaly detection or attack detection logic here


        # Function to analyze the traffic for anomalies or attacks


# Uncomment the line below to perform real-time analysis on sniffed traffic
# sniff(prn=analyze_traffic, store=0)


        # You can use the stored traffic data for analysis


# Function to send an email alert
def send_alert(subject, body):
    sender_email = "your_email@example.com"
    receiver_email = "recipient_email@example.com"
    smtp_server = "smtp.example.com"
    smtp_port = 587
    username = "your_email@example.com"
    password = "your_password"

    message = MIMEText(body)
    message["Subject"] = subject
    message["From"] = sender_email
    message["To"] = receiver_email

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(username, password)
        server.sendmail(sender_email, receiver_email, message.as_string())

# Function to analyze the traffic for anomalies or attacks
def analyze_traffic(packet):
    # Perform your anomaly detection or attack detection logic here
    # You can access the traffic data from the database and analyze it

    # If an anomaly or attack is detected, send an alert
    subject = "Network Traffic Alert"
    body = "Anomaly or attack detected in the network traffic!"
    send_alert(subject, body)

# Sniff network traffic and process packets
sniff(prn=store_traffic_data, store=0)

# Uncomment the line below to perform real-time analysis on sniffed traffic
# sniff(prn=analyze_traffic, store=0)
