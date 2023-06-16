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
dataset = []
boxplot_offset = 0.5
columns = ['vm1_downtime', 'vm2_downtime', 'vm3_downtime', 'vm4_downtime']
data = []

desired_order = ['HW_A_filtered_solr.csv', 'SW_A_filtered_solr.csv', 'CRASH_L1_filtered_solr.csv', 'CRASH_L2_filtered_solr.csv', 'HANG_L1_filtered_solr.csv' ,'HANG_L2_filtered_solr.csv']  # Specify the desired order of files

files = [file_name for file_name in os.listdir(folder_path) if file_name.endswith('.csv')]

# Sort the files based on the desired order
sorted_files = sorted(files, key=lambda x: desired_order.index(x))

for i, file_name in enumerate(sorted_files):
    if file_name.endswith('.csv'):
        file_path = os.path.join(folder_path, file_name)
        df = pd.read_csv(file_path)
        dfvm1 = df.copy()
        dfvm2 = df.copy()
        dfvm3 = df.copy()
        dfvm4 = df.copy()
        dfvm1.drop(columns=["vm2_downtime", "vm3_downtime", "vm4_downtime"], inplace=True)
        dfvm2.drop(columns=["vm1_downtime", "vm3_downtime", "vm4_downtime"], inplace=True)
        dfvm3.drop(columns=["vm1_downtime", "vm2_downtime", "vm4_downtime"], inplace=True)
        dfvm4.drop(columns=["vm1_downtime", "vm2_downtime", "vm3_downtime"], inplace=True)
        dfvm1["which_vm"] = "VM 1"
        dfvm2["which_vm"] = "VM 2"
        dfvm3["which_vm"] = "VM 3"
        dfvm4["which_vm"] = "VM 4"
        dfvm1.rename(columns={"vm1_downtime": "downtime"}, inplace=True)
        dfvm2.rename(columns={"vm2_downtime": "downtime"}, inplace=True)
        dfvm3.rename(columns={"vm3_downtime": "downtime"}, inplace=True)
        dfvm4.rename(columns={"vm4_downtime": "downtime"}, inplace=True)
        dfvm1["downtime"] = dfvm1["downtime"] - (dfvm1["real_detection_lat"] / 1000.0)
        dfvm2["downtime"] = dfvm2["downtime"] - (dfvm2["real_detection_lat"] / 1000.0)
        dfvm3["downtime"] = dfvm3["downtime"] - (dfvm3["real_detection_lat"] / 1000.0)
        dfvm4["downtime"] = dfvm4["downtime"] - (dfvm4["real_detection_lat"] / 1000.0)
        df = pd.concat([dfvm1, dfvm2, dfvm3, dfvm4])

        downtime = df['downtime']
        downtime = downtime.dropna()
        median_real = downtime.median()
        lower_limit_real = downtime.quantile(0.25)
        upper_limit_real = downtime.quantile(0.75)

        dataset.append(file_name.replace('_filtered_solr.csv', ''))
        data.append(downtime.tolist())

        print("File: " + str(file_name))
        print("Median: " + str(median_real))
        print("Lower Limit: " + str(lower_limit_real))
        print("Upper Limit: " + str(upper_limit_real))
        print("\n")


plt.figure(figsize=(10, 8))
sns.boxplot(data=data, palette="Blues")
plt.xticks(range(len(dataset)), dataset, fontsize=16, rotation=45)
plt.ylim(0, 800)
y_ticks = range(50, 850, 50)
plt.yticks(y_ticks, fontsize=16)
plt.xlabel("Dataset",fontsize=14)
plt.ylabel("Downtime (s)",fontsize=14)


plt.savefig('boxplot_downtime_sns.pdf', bbox_inches='tight', pad_inches=0)