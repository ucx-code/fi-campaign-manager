import os
import pandas as pd
import sys

# set the path to the folder containing the CSV files
folder_path = sys.argv[1]

# get a list of all CSV files in the folder
csv_files = [f for f in os.listdir(folder_path)]

# concatenate all CSV files into a single DataFrame
df = pd.concat(map(pd.read_csv, [os.path.join(folder_path, f) for f in csv_files]))

# save the merged DataFrame to a new CSV file
df.to_csv('merged_data.csv', index=False)
