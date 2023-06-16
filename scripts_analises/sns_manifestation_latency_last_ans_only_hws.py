import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from matplotlib.ticker import MultipleLocator
import numpy as np
from math import *
import sys
import os

plt.switch_backend('Agg')  # Set the backend to Agg
sns.set(style="whitegrid")

folder_path = sys.argv[1]
fig, ax = plt.subplots(figsize=(9, 7))
dataset = []
boxplot_offset = 0.5
data =[]

desired_order = ['HW_A_manifestation.csv', 'HW_B_manifestation.csv', 'CRASH_L1_manifestation.csv', 'CRASH_L2_manifestation.csv', 'HANG_L1_manifestation.csv' ,'HANG_L2_manifestation.csv']  # Specify the desired order of files

files = [file_name for file_name in os.listdir(folder_path) if file_name.endswith('.csv')]

# Sort the files based on the desired order
sorted_files = sorted(files, key=lambda x: desired_order.index(x))


for i, file_name in enumerate(sorted_files):
    if file_name.endswith('.csv'):
        file_path = os.path.join(folder_path, file_name)
        df = pd.read_csv(file_path)
        manifestation = df[df['manifestation'] < 2000]['manifestation'].dropna()

        
            

        min_real =  manifestation.min()
        min_line_real = manifestation.idxmin() + 1
        max_real = manifestation.max()
        max_line_real = manifestation.idxmax() + 1
        avg_real = manifestation.mean()
        median_real = manifestation.median()
        lower_limit_real = manifestation.quantile(0.25)
        upper_limit_real = manifestation.quantile(0.75)

        print("File: " + str(file_name))
        print("Min: " + str(min_real) + " line: " + str(min_line_real))
        print("Max: " + str(max_real) + " line: " + str(max_line_real))
        print("Avg: " + str(avg_real))
        print("Median: " + str(median_real))
        print("Lower Limit: " + str(lower_limit_real))
        print("Upper Limit: " + str(upper_limit_real))
    
        data.append(manifestation.tolist())
        dataset.append(file_name.replace('_manifestation.csv', ''))
        print("\n")

plt.figure(figsize=(10, 8))
sns.boxplot(data=data, palette="Blues")

plt.xticks(range(len(dataset)), dataset, rotation=45, fontsize=14)
plt.ylim(-12, 40)
y_ticks = range(-12, 42, 2)
plt.yticks(y_ticks, fontsize=14)
plt.xlabel("Dataset",fontsize=14)
plt.ylabel("Manifestation Latency (s)",fontsize=14)


plt.savefig('manifestation_latency_last_ans_hws_sns.pdf', bbox_inches='tight', pad_inches=0)
