import pandas as pd
import sys
import numpy as np

csv_file = sys.argv[1]
df = pd.read_csv(csv_file)



df['operator'] = df['PATCH_FILE'].str.extract(r'\.(.*?)\d')
grouped = df.groupby("operator").size()

# Iterate over each operator and print the counts
for operator, count in grouped.items():
    crashes = df[df["operator"] == operator]["crash_tstamp"].count()
    print("Operator: " + str(operator) + " total: " + str(count) + " crashes: " + str(crashes))

