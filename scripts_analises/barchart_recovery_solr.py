import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import sys
import os
from matplotlib import patches
folder_path = sys.argv[1]
plt.switch_backend('Agg')  # Set the backend to Agg
sns.set(style="whitegrid")
colors = ['blue', 'orange', 'green', 'red','yellow','purple']
palette = sns.color_palette('tab10', n_colors=len(colors))

legends = []  # List to store legend labels
data = []

for i, file_name in enumerate(os.listdir(folder_path)):
    if file_name.endswith('.csv'):
        file_path = os.path.join(folder_path, file_name)
        df = pd.read_csv(file_path)

        total_rows = len(df)
        count_probabilities = df['count_recovered_vms_solr'].value_counts() / total_rows * 100

        count_values = count_probabilities.index.sort_values()
        probabilities = count_probabilities[count_values]

        legend_label = file_name.replace('_filtered_solr.csv', '')
        legends.append(legend_label)
        print("Dataset " + str(legend_label))

        dataset_data = pd.DataFrame({'Count': count_values, 'Probability': probabilities, 'Dataset': legend_label})
        dataset_data['Dataset'] = dataset_data['Dataset'].astype('category')  # Ensure proper ordering in the legend
        data.append(dataset_data)

        for count, probability in zip(count_values, probabilities):
            print("Count of Recovered VMs (Solr): " + str(count) + " probability: " + str(probability) + "%")
        print("\n")

df_concatenated = pd.concat(data)

plt.figure(figsize=(10, 6))
sns.barplot(x='Count', y='Probability', hue='Dataset', data=df_concatenated, palette=palette)

plt.xlabel('Count of Recovered VMs (solr)',fontsize=12)
plt.ylabel('Probability (%)', fontsize=12)

plt.yticks(range(0, 81, 5),fontsize=14)
plt.xticks(plt.gca().get_xticks(), [int(x) for x in plt.gca().get_xticks()],fontsize=14)

legend_elements = []
for i, legend_label in enumerate(legends):
    legend_elements.append(patches.Patch(facecolor=palette[i], label=legend_label))

plt.legend(handles=legend_elements)


plt.savefig('recovery_barchart_solr.pdf', bbox_inches='tight', pad_inches=0)
