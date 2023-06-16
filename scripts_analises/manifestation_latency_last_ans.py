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

for i, file_name in enumerate(os.listdir(folder_path)):
    if file_name.endswith('.csv'):
        file_path = os.path.join(folder_path, file_name)
        df = pd.read_csv(file_path)
        manifestation = df['manifestation'].dropna()
        
            

        min_real =  manifestation.min()
        min_line_real = manifestation.idxmin() + 1
        max_real = manifestation.max()
        max_line_real = manifestation.idxmax() + 1
        avg_real = manifestation.mean()

        print("File: " + str(file_name))
        print("Min: " + str(min_real) + " line: " + str(min_line_real))
        print("Max: " + str(max_real) + " line: " + str(max_line_real))
        print("Avg: " + str(avg_real))
    
        dataset.append(file_name.replace('_manifestation.csv', ''))
        positions.append(i+1 + boxplot_offset) 
        boxplot = ax.boxplot(manifestation, positions=[i+1 + boxplot_offset])

        median = boxplot['medians'][0].get_ydata()[0]
        lower_limit = boxplot['caps'][0].get_ydata()[0]
        upper_limit = boxplot['caps'][1].get_ydata()[0]
        print("Median: " + str(median))
        print("Lower limit: " + str(lower_limit))
        print("Upper limit: " + str(upper_limit))


ax.set_xlim(1, len(os.listdir(folder_path)) + 1) 


matplotlib.pyplot.yticks(fontsize=14)
ax.set_xlabel('Dataset',fontsize=12)
ax.set_ylabel('Manifestation Latency (s)',fontsize=12)
y_min = -10
y_max = 600
ax.set_ylim(y_min, y_max)
ax.yaxis.set_major_locator(MultipleLocator(30))


ax.set_xticks(positions)
ax.set_xticklabels(dataset, rotation=45, ha='right',fontsize=14)

plt.savefig('manifestation_latency_ans_2.pdf', bbox_inches='tight', pad_inches=0)
