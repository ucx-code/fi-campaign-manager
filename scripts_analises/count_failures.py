import pandas as pd
import numpy as np
import sys

master = sys.argv[1]
# Read the CSV file into a pandas dataframe
df = pd.read_csv(master)


df = df.fillna(value=np.nan)

print(str(df['CSV_PATH1'].count()) + " experiments")
column_name = 'crash_tstamp'
count = df[column_name].count()

print("The number of crashes is: " + str(count))
