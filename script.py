import hashlib
import os
import re
import csv
import requests
from datetime import datetime

# URL to fetch known IOCs
IOC_DATABASE_URL = "https://urlhaus.abuse.ch/downloads/"\
                    "plaintext.txt"


def analyze_file(file_path):
    """
    Analyze a file and extract metadata, hashes, and potential indicators of compromise.

    Args:
        file_path (str): The path to the file to analyze.

    Returns:
        dict: A dictionary containing the file analysis results.
    """
    analysis_results = {
        'file_path': file_path,
        'file_size': os.path.getsize(file_path),
        'file_extension': os.path.splitext(file_path)[1],
        'created_time': os.path.getctime(file_path),
        'modified_time': os.path.getmtime(file_path),
        'accessed_time': os.path.getatime(file_path),
        'md5_hash': calculate_hash(file_path, 'md5'),
        'sha1_hash': calculate_hash(file_path, 'sha1'),
        'sha256_hash': calculate_hash(file_path, 'sha256'),
        'potential_iocs': []
    }

    with open(file_path, 'rb') as file:
        file_content = file.read()
        analysis_results['potential_iocs'] = find_potential_iocs(file_content, known_iocs)

    return analysis_results

def calculate_hash(file_path, algorithm):
    """
    Calculate the hash value of a file using the specified algorithm.

    Args:
        file_path (str): The path to the file.
        algorithm (str): The hashing algorithm to use (e.g., 'md5', 'sha1', 'sha256').

    Returns:
        str: The hash value of the file.
    """
    hash_obj = hashlib.new(algorithm)
    with open(file_path, 'rb') as file:
        while True:
            data = file.read(65536)  # Read in 64KB chunks
            if not data:
                break
            hash_obj.update(data)
    return hash_obj.hexdigest()

def find_potential_iocs(file_content, known_iocs):
    """
    Find potential indicators of compromise (IOCs) in the file content.

    Args:
        file_content (bytes): The content of the file.
        known_iocs (list): A list of known IOC patterns.

    Returns:
        list: A list of potential IOCs found in the file content.
    """
    potential_iocs = []
    for pattern in known_iocs:
        matches = re.findall(pattern, file_content)
        potential_iocs.extend(match.decode() for match in matches)

    return list(set(potential_iocs))

def fetch_known_iocs():
    """
    Fetch a list of known IOCs from a specified URL.

    Returns:
        list: A list of known IOC patterns.
    """
    try:
        response = requests.get(IOC_DATABASE_URL)
        response.raise_for_status()
        known_iocs = response.text.splitlines()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching IOC database: {e}")
        known_iocs = [
            rb'[a-fA-F\d]{32}',  # MD5 hash
            rb'[a-fA-F\d]{40}',  # SHA-1 hash
            rb'[a-fA-F\d]{64}',  # SHA-256 hash
            rb'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',  # IPv4 address
            rb'(([a-fA-F\d]{1,4}:){7}[a-fA-F\d]{1,4})',  # IPv6 address
            rb'[a-zA-Z\d-]{,63}\.([a-zA-Z\d-]{,63}\.)*[a-zA-Z\d-]{,63}',  # Domain name
            rb'[a-zA-Z\d+_-]+@[a-zA-Z\d+_-]+\.[a-zA-Z\d+_-]+',  # Email address
        ]
    return known_iocs

def analyze_directory(directory_path, output_file='file_analysis.csv'):
    """
    Analyze all files in a directory and its subdirectories.

    Args:
        directory_path (str): The path to the directory to analyze.
        output_file (str): The name of the output file to write the analysis results.
    """
    analysis_results = []
    known_iocs = fetch_known_iocs()

    for root, _, files in os.walk(directory_path):
        for filename in files:
            file_path = os.path.join(root, filename)
            analysis_results.append(analyze_file(file_path))

    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = [
            'file_path', 'file_size', 'file_extension', 'created_time', 'modified_time',
            'accessed_time', 'md5_hash', 'sha1_hash', 'sha256_hash', 'potential_iocs', 'suspicious'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for result in analysis_results:
            result['created_time'] = datetime.fromtimestamp(result['created_time']).isoformat()
            result['modified_time'] = datetime.fromtimestamp(result['modified_time']).isoformat()
            result['accessed_time'] = datetime.fromtimestamp(result['accessed_time']).isoformat()
            result['potential_iocs'] = ','.join(result['potential_iocs'])
            result['suspicious'] = 'Yes' if result['potential_iocs'] else 'No'
            writer.writerow(result)

if __name__ == "__main__":
    directory_path = input("Enter the directory path to analyze: ")
    analyze_directory(directory_path)
    print("File analysis completed. Results written to 'file_analysis.csv'.")