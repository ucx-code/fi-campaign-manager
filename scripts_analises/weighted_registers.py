import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import sys
import numpy as np

csv_file = sys.argv[1]
df = pd.read_csv(csv_file)

max_experiments = df['Experiments'].max()

#2049 -> total de experiemnts

for index, row in df.iterrows():
    failures = row['Failures']
    experiments = row['Experiments']
    df.loc[index, 'Failures'] = (failures * max_experiments) / experiments
    df.loc[index, 'Experiments'] = max_experiments

print(df)
total_experiments = int(df['Experiments'].sum())
total_failures = int(df['Failures'].sum())
failure_percentage = (total_failures / float(total_experiments)) * 100

print("Total Experiments: " + str(total_experiments))
print("Total Failures: " + str(total_failures))
print("Failure Percentage: " + str(failure_percentage))
