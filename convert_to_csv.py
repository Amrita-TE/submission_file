import requests
import csv
try:
    response = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0")
    response.raise_for_status()  # Check for HTTP errors
    json_data = response.json()  # Assuming the response contains JSON data
except requests.exceptions.RequestException as e:
    print(f"Error fetching data from URL: {e}")
    exit(1)
except ValueError as e:
    print(f"Error decoding JSON: {e}")
    print(f"Response content: {response.text}")
    exit(1)

# Step 2: Extract the list of vulnerabilities
if 'vulnerabilities' in json_data:
    vulnerabilities = json_data['vulnerabilities']
else:
    print("JSON data does not contain 'vulnerabilities' key.")
    exit(1)

# Step 3: Define the fields to be extracted
fields = ['cve_id', 'published_date', 'last_modified_date', 'description', 'cvss_score']

# Step 4: Write the data to a CSV file
csv_file = 'vulnerabilities.csv'
try:
    with open(csv_file, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()

        for vuln in vulnerabilities:
            cve = vuln['cve']
            row = {
                'cve_id': cve.get('id'),
                'published_date': cve.get('published'),
                'last_modified_date': cve.get('lastModified'),
                'description': next((desc['value'] for desc in cve.get('descriptions', []) if desc['lang'] == 'en'), ''),
                'cvss_score': next((metric['cvssData']['baseScore'] for metric in cve.get('metrics', {}).get('cvssMetricV2', [])), ''),
            }
            writer.writerow(row)
    print(f'Data has been written to {csv_file}')
except IOError as e:
    print(f"Error writing to CSV file: {e}")
    exit(1)