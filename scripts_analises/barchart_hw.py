import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import sys
import numpy as np
import seaborn as sns

plt.switch_backend('Agg')  # Set the backend to Agg
sns.set(style="whitegrid")
colors = ['blue', 'orange']
palette = sns.color_palette('tab10', n_colors=len(colors))

csv_file = sys.argv[1]
csv_file2 = sys.argv[2]
df = pd.read_csv(csv_file)
df2 = pd.read_csv(csv_file2)

# Define the register names and their corresponding values
register_names = {
    0: 'rip',
    1: 'rsp',
    2: 'rbp',
    3: 'rax',
    4: 'rbx',
    5: 'rcx',
    6: 'rdx',
    7: 'r8',
    8: 'r9',
    9: 'r10',
    10: 'r11',
    11: 'r12',
    12: 'r13',
    13: 'r14',
    14: 'r15',
}

# Map the values in the "INJ_REG" column to register names
df['Register'] = df['INJ_REG'].map(register_names)
df2['Register'] = df2['INJ_REG'].map(register_names)

register_counts1 = df['Register'].value_counts().sort_index()
register_counts2 = df2['Register'].value_counts().sort_index()

register_percentages1 = (register_counts1 / len(df)) * 100
register_percentages2 = (register_counts2 / len(df2)) * 100

register_names = register_percentages1.index.tolist()
register_names.sort(key=lambda x: int(x[1:]) if x[1:].isdigit() else float('inf'))  

x = np.arange(len(register_names))
bar_width = 0.4


fig, ax = plt.subplots(figsize=(7, 5))

ax.bar(x, register_percentages1, width=bar_width, color=palette[0], label='HW_A')
ax.bar(x + bar_width, register_percentages2, width=bar_width, color=palette[1], label='HW_B')


ax.set_xlabel('Register')
ax.set_ylabel('Percentage (%)')
ax.set_xticks(x + bar_width / 2)
ax.set_xticklabels(register_names, rotation=45)


ax.legend()

plt.savefig('register_distribution.pdf',bbox_inches='tight', pad_inches=0)
