import pandas as pd
import matplotlib
matplotlib.use('Agg')  # Set the backend to Agg
import matplotlib.pyplot as plt
from matplotlib.ticker import MultipleLocator
import numpy as np
from math import *
import sys


csv_file = sys.argv[1]
df = pd.read_csv(csv_file)

plt.boxplot(df['real_detection_lat'])

plt.xlabel('Dataset')
plt.ylabel('Real Detection Latency (ms)')
plt.title('Boxplot of Real Detection Latency', fontsize=18)
y_min = 30000
y_max = 100000
plt.ylim(y_min, y_max) 
plt.gca().yaxis.set_major_locator(MultipleLocator(5000)) 

plt.savefig('manifestation_latency_one.png')  
