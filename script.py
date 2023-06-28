#! /usr/bin/env python

import glob

file_list = glob.glob("*.log")
file_list.sort()

for file_name in file_list:
    with open(file_name, "r") as f:
        file_contents = f.read()
        parts = [int(part.strip()) for part in file_contents.split("\\") if part.strip()]
        if parts:
            min_val = min(parts)
            max_val = max(parts)
            avg_val = sum(parts) / len(parts)
            print(f"File: {file_name}, Min: {min_val}, Max: {max_val}, Avg: {avg_val}")