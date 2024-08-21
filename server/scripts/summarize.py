import os
import sys

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

    print(f"Average ACME Initiation Time: {avg_acme_initiation:.2f} seconds")
    print(f"Average DNS Propagation Time: {avg_dns_propagation:.2f} seconds")
    print(f"Average ACME Verification Time: {avg_acme_verification:.2f} seconds")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 summarize.py <directory>")
        sys.exit(1)

    directory = sys.argv[1]
    main(directory)
