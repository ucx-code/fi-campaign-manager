import pandas as pd
import sys
import numpy as np

csv_file = sys.argv[1]
df = pd.read_csv(csv_file)


df['real_detection_lat'] = df['crash_tstamp'] - df['fi_tstamp']
df.to_csv(csv_file + '_with_detection.csv', index=False)