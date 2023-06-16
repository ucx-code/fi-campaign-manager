import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import sys
import numpy as np
import re
import seaborn as sns

plt.switch_backend('Agg')  # Set the backend to Agg
sns.set(style="whitegrid")
colors = ['blue', 'orange']
palette = sns.color_palette('tab10', n_colors=len(colors))

csv_file = sys.argv[1]
csv_file2 = sys.argv[2]
df = pd.read_csv(csv_file)
df2 = pd.read_csv(csv_file2)

operators = {'MFC': 'MFC', 'MIA': 'MIA', 'MIFS': 'MIFS', 'WPFV': 'WPFV', 'MIEB': 'MIEB', 'MLAC': 'MLAC',
             'MVAE': 'MVAE', 'MVAV': 'MVAV', 'WAEP': 'WAEP', 'WLEC': 'WLEC', 'WVAV': 'WVAV'}

# Extract the operators from "PATCH_FILE" column
df['Operator'] = df['PATCH_FILE'].apply(lambda x: re.search(r'\._([A-Za-z]+)_\d+\.patch', x).group(1) if re.search(r'\._([A-Za-z]+)_\d+\.patch', x) else None)
df2['Operator'] = df2['PATCH_FILE'].apply(lambda x: re.search(r'\._([A-Za-z]+)_\d+\.patch', x).group(1) if re.search(r'\._([A-Za-z]+)_\d+\.patch', x) else None)

operator_counts1 = df['Operator'].value_counts().sort_index()
operator_counts2 = df2['Operator'].value_counts().sort_index()

operator_percentages1 = (operator_counts1 / len(df)) * 100
operator_percentages2 = (operator_counts2 / len(df2)) * 100

operators_sorted = [op for op in operators.values() if op in operator_counts1.index or op in operator_counts2.index]
operators_sorted.sort()

x = np.arange(len(operators_sorted))
bar_width = 0.4

fig, ax = plt.subplots(figsize=(7, 5))

ax.bar(x, operator_percentages1[operators_sorted], width=bar_width,color=palette[0], label='SW_A')
ax.bar(x + bar_width, operator_percentages2[operators_sorted], width=bar_width, color=palette[1], label='SW_B')

ax.set_xlabel('Operator')
ax.set_ylabel('Percentage (%)')
ax.set_xticks(x + bar_width / 2)
ax.set_xticklabels(operators_sorted, rotation=45)

ax.legend()

plt.savefig('operator_distribution.pdf',bbox_inches='tight', pad_inches=0)
