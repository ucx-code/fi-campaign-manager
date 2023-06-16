import pandas as pd
import matplotlib
matplotlib.use('Agg')  # Set the backend to Agg
import matplotlib.pyplot as plt
from matplotlib.ticker import MultipleLocator
import numpy as np
from math import *
import sys
import os


folder_path = sys.argv[1]
fig, ax = plt.subplots(figsize=(9, 7))
dataset = []
positions = []
boxplot_offset = 0.5
columns = ['vm1_downtime','vm2_downtime','vm3_downtime','vm4_downtime']
for i, file_name in enumerate(os.listdir(folder_path)):
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

        dataset.append(file_name.replace('_filtered_solr.csv', ''))
        positions.append(i+1 + boxplot_offset) 
        ax.boxplot(downtime, positions=[i+1 + boxplot_offset])

ax.set_xlim(1, len(os.listdir(folder_path)) + 1) 

matplotlib.pyplot.yticks(fontsize=14)
ax.set_xlabel('Dataset',fontsize=12)
ax.set_ylabel('Downtime (s)',fontsize=12)
y_min = 0
y_max = 1000
ax.set_ylim(y_min, y_max)
ax.yaxis.set_major_locator(MultipleLocator(50))


ax.set_xticks(positions)
ax.set_xticklabels(dataset, rotation=45, ha='right',fontsize=14)

plt.savefig('downtime.pdf', bbox_inches='tight', pad_inches=0)
