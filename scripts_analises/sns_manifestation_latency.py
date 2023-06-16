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
for i, file_name in enumerate(os.listdir(folder_path)):
    if file_name.endswith('.csv'):
        file_path = os.path.join(folder_path, file_name)
        df = pd.read_csv(file_path)
        print("File: " + str(file_name))
        real_latency = df['real_detection_lat']/1000
    
            

        min_real =  real_latency.min()
        min_line_real = real_latency.idxmin() + 1
        max_real = real_latency.max()
        max_line_real = real_latency.idxmax() + 1
        avg_real = real_latency.mean()
        median_real = real_latency.median()
        lower_limit_real = real_latency.quantile(0.25)
        upper_limit_real = real_latency.quantile(0.75)

       
        print("Min: " + str(min_real) + " line: " + str(min_line_real))
        print("Max: " + str(max_real) + " line: " + str(max_line_real))
        print("Avg: " + str(avg_real))
        print("Median: " + str(median_real))
        print("Lower Limit: " + str(lower_limit_real))
        print("Upper Limit: " + str(upper_limit_real))

        data.append(real_latency.tolist())
        dataset.append(file_name.replace('_filtered.csv', ''))
        print("\n")



plt.figure(figsize=(10, 8))
sns.boxplot(data=data, palette="Blues")

plt.xticks(range(len(dataset)), dataset, rotation= 45, fontsize=14)
plt.ylim(20, 110)
y_ticks = range(20, 120, 5)
plt.yticks(y_ticks, fontsize=14)
plt.xlabel("Dataset",fontsize=14)
plt.ylabel("Real Detection Latency (s)",fontsize=14)


plt.savefig('manifestation_latency_sns.pdf', bbox_inches='tight', pad_inches=0)