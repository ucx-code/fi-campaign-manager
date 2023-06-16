import pandas as pd
import sys
import numpy as np

csv_file = sys.argv[1]
df = pd.read_csv(csv_file)

import pandas as pd


grouped = df.groupby("INJ_REG").size()


for inj_reg, count in grouped.items():
    crashes = df[df["INJ_REG"] == inj_reg]["crash_tstamp"].count()
    print("INJ_REG: " + str(inj_reg) + " total: " + str(count) + " crashes: " + str(crashes))