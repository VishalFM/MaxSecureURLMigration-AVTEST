import os
import csv
import json
import requests

# Directory containing the CSV files
directory_path = "C:\\Users\\VISHAL\\OneDrive\\Desktop\\Flairminds\\Fable malware detection - Master\\Test Data"
vendor_name = "VishalBro"

# directory_path = "/home/ubuntu/Files/MRGURLs-CSV"
# vendor_name = "MRG"

# directory_path = "/home/ubuntu/Files/AvtestURL"
# vendor_name = "Avtest"

# Fixed values for VendorName and EntryStatus
entry_status = 1

# API endpoint
api_url = "http://localhost:5000/malicious_urls"
# api_url = "http://172.30.5.125/malicious_urls"

# Array to store failed file names
failed_files = []

def read_csv_file(file_path):
    try:
        records = []
        with open(file_path, mode='r', newline='', encoding='utf-8') as file:
            csv_reader = csv.DictReader(file)
            for row in csv_reader:
                record = {
                    "URL": row.get("URL", ""),
                    "VendorName": vendor_name,
                    "EntryStatus": entry_status,
                    "Score": float(row.get("DETECTION_RATE", 0.0))
                }
                records.append(record)
        return records
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return None

def send_data_to_api(data):
    try:
        headers = {"Content-Type": "application/json"}
        response = requests.post(api_url, headers=headers, data=json.dumps(data))
        return response.status_code == 200 or response.status_code == 201
    except Exception as e:
        print(f"Error sending data to API: {e}")
        return False

try:
    # Get all CSV file names
    csv_files = [f for f in os.listdir(directory_path) if f.endswith('.csv')]
    print(f"Found {len(csv_files)} CSV files.")

    for file_name in csv_files:
        file_path = os.path.join(directory_path, file_name)
        try:
            print(f"Processing file: {file_name}")

            # Read and parse CSV file
            records = read_csv_file(file_path)
            if records is None:
                failed_files.append(file_name)
                continue
            
            print(f"File - {file_name} contains {len(records)} records.")
            # Batch data in groups of 1000
            for i in range(0, len(records), 1500):
                batch = records[i:i + 1500]
                if not send_data_to_api(batch):
                    raise Exception("Failed to send data to API.")

            print(f"Successfully processed file: {file_name}")
        except Exception as ex:
            print(f"Failed to process file: {file_name}. Error: {ex}")
            failed_files.append(file_name)

    # Log failed files
    if failed_files:
        print("The following files failed to process:")
        for failed_file in failed_files:
            print(failed_file)
except Exception as ex:
    print(f"An error occurred: {ex}")

print("Processing complete.")
