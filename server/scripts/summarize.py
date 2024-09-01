import os
import re
import sys

# Function to convert 'real' time from the format 'XmYs' to seconds
def convert_to_seconds(real_time):
    match = re.match(r'(\d+)m(\d+\.\d+)s', real_time)
    if match:
        minutes = int(match.group(1))
        seconds = float(match.group(2))
        return minutes * 60 + seconds
    else:
        return 0.0

# Function to parse a single log file
def parse_log_file(filepath):
    with open(filepath, 'r') as file:
        real_times = []
        for line in file:
            line = line.strip()
            if line.startswith('real'):
                _, real_time = line.split()
                real_times.append(convert_to_seconds(real_time))
        return real_times

def is_valid_directory(directory):
    return os.path.isdir(directory)

def find_dat_files(directory):
    dat_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.dat'):
                dat_files.append(os.path.join(root, file))
    return dat_files

def parse_dat_file(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
        # The first line is metadata, so we skip it.
        numbers = [float(line.split()[-2]) for line in lines[1:]]
        
        # Categorize and sum the times
        acme_initiation = sum(numbers[:3])  # Sum the first three
        dns_propagation = numbers[3]        # Fourth one
        acme_verification = sum(numbers[4:]) # Sum the fifth and sixth

    return acme_initiation, dns_propagation, acme_verification

def parse_circ_for_proof_gen():
    # loop over files in ../bench/dat
    total_time = 0
    total_runs = 0
    for filename in os.listdir('../bench/dat'):
        # if filename ends with man.log, skip it
        if filename.endswith('man.log'):
            continue
        elif filename.endswith('.log'):
            filepath = os.path.join('../bench/dat', filename)
            real_times = parse_log_file(filepath)
            total_time += sum(real_times)
            total_runs += len(real_times)
    return total_time / total_runs

def main(directory):
    if not is_valid_directory(directory):
        print(f"Error: {directory} is not a valid directory.")
        sys.exit(1)

    dat_files = find_dat_files(directory)

    if not dat_files:
        print(f"No .dat files found in {directory}.")
        sys.exit(0)

    total_acme_initiation = 0
    total_dns_propagation = 0
    total_acme_verification = 0

    for dat_file in dat_files:
        acme_initiation, dns_propagation, acme_verification = parse_dat_file(dat_file)
        total_acme_initiation += acme_initiation
        total_dns_propagation += dns_propagation
        total_acme_verification += acme_verification

    avg_acme_initiation = total_acme_initiation / len(dat_files)
    avg_dns_propagation = total_dns_propagation / len(dat_files)
    avg_acme_verification = total_acme_verification / len(dat_files)
    avg_proof_gen = parse_circ_for_proof_gen()

    print(f"Average Proof Generation Time: {avg_proof_gen:.2f} seconds")
    print(f"Average ACME Initiation Time: {avg_acme_initiation:.2f} seconds")
    print(f"Average DNS Propagation Time: 30 second minimum from certbot, (you took {avg_dns_propagation:.2f} seconds)")
    print(f"Average ACME Verification Time: {avg_acme_verification:.2f} seconds")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 summarize.py <directory>")
        sys.exit(1)

    directory = sys.argv[1]
    main(directory)
