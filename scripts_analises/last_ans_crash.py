import pandas as pd
import sys
import numpy as np
import os


def get_last_ans(df):
   answered = df[df["code"] == 200].sort_values(by="received_ts", ascending=False)
   
   last_ans_ts = answered.iloc[0,:]["received_ts"]
   return last_ans_ts


csv_file = sys.argv[1]
master = pd.read_csv(csv_file)

# Ensure crash was detected
print("Rows before: " + str(len(master.index)))
master = master[master["crash_tstamp"].isna()]
print("Rows after: " + str(len(master.index)))  

# Iterate over each row
for index, row in master.iterrows():
    print(str(len(master.index)))
    crash_tstamp = row['crash_tstamp']/1000
    fi_tstamp = row['fi_tstamp']/1000
    print("crash_tstamp: " + str(crash_tstamp))
    print("fi_tstamp: " + str(fi_tstamp))


    dg1 = pd.read_csv(row['CSV_PATH1'])
    dg1_filtered = dg1[dg1['received_ts']<=crash_tstamp]
    master.loc[index, 'vm1_last_ans_ts'] = get_last_ans(dg1_filtered)

    dg2 = pd.read_csv(row['CSV_PATH2'])
    dg2_filtered = dg2[dg2['received_ts']<=crash_tstamp]
    master.loc[index, 'vm2_last_ans_ts'] = get_last_ans(dg2_filtered)

    dg3 = pd.read_csv(row['CSV_PATH3'])
    dg3_filtered = dg3[dg3['received_ts']<=crash_tstamp]
    master.loc[index, 'vm3_last_ans_ts'] = get_last_ans(dg3_filtered)
    
    dg4 = pd.read_csv(row['CSV_PATH4'])
    dg4_filtered = dg4[dg4['received_ts']<=crash_tstamp]
    master.loc[index, 'vm4_last_ans_ts'] = get_last_ans(dg4_filtered)

    max_value = master[['vm1_last_ans_ts', 'vm2_last_ans_ts', 'vm3_last_ans_ts', 'vm4_last_ans_ts']].max().max()
    print("max_value: " + str(max_value))
    master.loc[index, 'manifestation'] = max_value - (fi_tstamp)
# Save the modified DataFrame to a new CSV file
master.to_csv('master_updated.csv', index=False)


