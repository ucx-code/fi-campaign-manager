import os
import glob
import matplotlib as mpl
mpl.use('Agg')
import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd
import sys


sns.set()
sns.set_style("whitegrid")

# List the CSV files in the folder
csv_folder = sys.argv[1]
csv_files = glob.glob(os.path.join(csv_folder, '*.csv'))

colors = ['blue', 'orange', 'green', 'red']

fig, ax = plt.subplots(figsize=(12, 8))

for i, csv_file in enumerate(csv_files):
    df = pd.read_csv(csv_file, header=0)
    df.dropna(subset=['count_recovered_vms_solr'], inplace=True)
    
    unique_values_solr = df['count_recovered_vms_solr'].unique()
    unique_values_solr.sort()
    total_rows = len(df)
    percentages_solr = [(df['count_recovered_vms_solr'] == value).sum() / total_rows * 100 for value in unique_values_solr] 
    
    unique_values_system = df['count_recovered_vms'].unique()
    unique_values_system.sort()
    percentages_system = [(df['count_recovered_vms'] == value).sum() / total_rows * 100 for value in unique_values_system] 
    
    print(percentages_system)
    ax.hist(df['count_recovered_vms_solr'], bins=unique_values_solr, cumulative=-1, density=True,
            label=os.path.basename(csv_file).replace('_filtered_solr.csv', '') + ' (solr)', linewidth=1.8, histtype='step', linestyle='dashed', color=colors[i])
    
    ax.hist(df['count_recovered_vms'], bins=unique_values_system, cumulative=-1, density=True,
            label=os.path.basename(csv_file).replace('_filtered_solr.csv', '') + ' (system)', linewidth=1.8, histtype='step', color=colors[i])

ax.set_ylim(0, 100)
ax.set_xlim(-0.25, 4.25)  
ax.set_xticks(range(5))  
ax.set_xlabel('Count of Recovered VMs')
ax.set_ylabel('Percentage (%)')
ax.legend()
plt.savefig('cumulative_hist.pdf', bbox_inches='tight')
