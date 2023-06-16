import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import sys 
import os
import glob
import seaborn as sns




sns.set()
sns.set_style("whitegrid")
folder_path = sys.argv[1]



colors = ['blue', 'orange', 'green', 'red', 'yellow', 'purple']
palette = sns.color_palette('tab10', n_colors=len(colors))
fig, ax = plt.subplots(figsize=(10, 6))

legends = []  # List to store legend labels

desired_order = ['HW_A_filtered_solr.csv', 'SW_A_filtered_solr.csv', 'CRASH_L1_filtered_solr.csv', 'CRASH_L2_filtered_solr.csv', 'HANG_L1_filtered_solr.csv' ,'HANG_L2_filtered_solr.csv']
files = [file_name for file_name in os.listdir(folder_path) if file_name.endswith('.csv')]


sorted_files = sorted(files, key=lambda x: desired_order.index(x))


for i, file_name in enumerate(sorted_files):
    if file_name.endswith('.csv'):
        file_path = os.path.join(folder_path, file_name)
        df = pd.read_csv(file_path)
    
    df = df.dropna(subset=['count_recovered_vms_solr'])
    unique_values_solr = df['count_recovered_vms_solr'].unique()
    unique_values_solr.sort()

    total_rows = len(df)

    
    percentages_os =  [len(df[df['count_recovered_vms_solr']==value]) / total_rows * 100 for value in unique_values_solr]
 
    ax.hist(df['count_recovered_vms_solr'], bins=unique_values_solr, cumulative=-1, density=True,
        label=os.path.basename(file_name).replace('_filtered_solr.csv', ''), linewidth=1.8, histtype='step', color=palette[i])
    



ax.set_xlim(-0.25, 4.25)  
ax.set_xticks(range(5))
ax.set_xticklabels(range(0, 5),fontsize=14)
ax.set_xlabel('Count of Recovered VMs (solr)')
ax.set_ylabel('Percentage [0:1]')
ax.legend()
plt.savefig('cumulative_hist_solr.pdf', bbox_inches='tight', pad_inches=0)

