import requests
import sys
url = sys.argv[1] 
token = sys.argv[2] 
file_name = sys.argv[3]
scan_type = sys.argv[4]
headers = {
    'Authorization': 'Token ' + token
}
print(f'Import {file_name}')
data = {
    'active': True,
    'verified': True,
    'scan_type': scan_type,
    'minimum_severity': 'Low',
    'engagement': 1
}
files = {
    'file': open(file_name, 'rb')
}
response = requests.post(url, headers=headers, data=data, files=files, verify=False)
if response.status_code == 201:
    print('Scan results imported successfully!!!')
else:
    print(f'Failed to import scan results: {response.content}')
