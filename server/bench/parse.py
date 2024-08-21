import os
import re

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

# Function to process all log files in the dat folder
def process_logs(dat_folder):
    for filename in os.listdir(dat_folder):
        if filename.endswith('.log'):
            filepath = os.path.join(dat_folder, filename)
            real_times = parse_log_file(filepath)
            k = len(real_times)
            if k > 0:
                average_time = sum(real_times) / k
                name = filename.split('.')[0]
                print(f"{k} iterations of {name}: {average_time:.2f} seconds")

# Main execution
if __name__ == "__main__":
    dat_folder = './dat'  # Replace with your actual dat folder path
    process_logs(dat_folder)
