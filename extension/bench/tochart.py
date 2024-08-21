import os
import re
import base64

# get the number of bytes in several files when converted from base64 to raw bytes
def get_combined_cert_size(paths):
    total = 0
    for path in paths:
        with open(path, 'r') as file:
            content = file.read()
            # remove newlines and base64 header/footer
            content = content.replace("\n", "").replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "")
            # convert to raw bytes
            raw = base64.b64decode(content)
            total += len(raw)
    return total

# get the number of bytes in a folder
def get_folder_size(folder):
    total = 0
    for root, dirs, files in os.walk(folder):
        for file in files:
            total += os.path.getsize(os.path.join(root, file))
    return total

# Define the directory structure
prefixes = ['nope', 'dv']
sub_dirs = ['nope', 'dv']
filepaths = []
for sub_dir in sub_dirs:
    for p in prefixes:
        filename = p+'-'+sub_dir+".txt"
        file_path = os.path.join(sub_dir, filename)
        filepaths.append(file_path)

filepaths.append(os.path.join("dnssec-chain", "dnssec.txt"))

# Regular expression to extract numbers
regex = r"full Average=(\d+\.\d+) ms, range (\d+\.\d+)-(\d+\.\d+) ms std: (\d+\.\d+) ms"

# Dictionary to store the results
results = {}

# Function to parse the content of a file
def parse_file_content(content):
    match = re.search(regex, content)
    if match:
        return {
            'Average': float(match.group(1)),
            'Min': float(match.group(2)),
            'Max': float(match.group(3)),
            'Std': float(match.group(4))
        }
    else:
        return None

# Traverse through the directory structure
for file_path in filepaths:
    with open(file_path, 'r') as file:
        content = file.read()
        results[str(file_path).split("/")[-1]] = parse_file_content(content)

headers = ['Server', 'Client','Size', 'Time', 'Variance']
print('\t'.join(headers))
print('-' * 40)

dv_chain_size = get_combined_cert_size(["cert/dv.pem", "cert/r11.pem"])
nope_chain_size = get_combined_cert_size(["cert/nope.pem", "cert/r11.pem"])
dnssec_size = get_folder_size("dnssec-chain/data")

res = results["dv-dv.txt"]
dv_dv = ['DV', 'DV', str(dv_chain_size), f'{res["Average"]:.1f}', f'{res["Std"]:.1f}']
print('\t'.join(dv_dv))

res = results["dv-nope.txt"]
dv_nope = ['DV', 'NOPE', str(dv_chain_size), f'{res["Average"]:.1f}', f'{res["Std"]:.1f}']
print('\t'.join(dv_nope))

res = results["nope-dv.txt"]
nope_dv = ['NOPE', 'DV', str(nope_chain_size), f'{res["Average"]:.1f}', f'{res["Std"]:.1f}']
print('\t'.join(nope_dv))

res = results["nope-nope.txt"]
nope_nope = ['NOPE', 'NOPE', str(nope_chain_size), f'{res["Average"]:.1f}', f'{res["Std"]:.1f}']
print('\t'.join(nope_nope))

res = results["dnssec.txt"]
dnssec = ['DNSSEC', '-', str(dnssec_size), f'{res["Average"]:.1f}', f'{res["Std"]:.1f}']
print('\t'.join(dnssec))
