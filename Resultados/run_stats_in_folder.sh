#!/bin/sh
DATA_PATH=$1
N_VMS=$2

GLOBAL_BASE=stats_$(basename $DATA_PATH)
GLOBAL_FILE=stats_$(basename $DATA_PATH).csv


rm $GLOBAL_FILE

# Calculate performance, migration success, etc. stats for each VM and every run
for f in $DATA_PATH/dg1_*.csv; do 
   B=$(basename $f)
   I=`echo $B | grep -o '_[[:digit:]]\+_'  | cut -d _ -f 2`
   echo "B: $B I: $I"
   bash run_stats_for_run.sh $DATA_PATH $I $N_VMS &
done

wait


# Add some extra info to master.csv
python2 common/extra_info_to_master.py $DATA_PATH/master.csv


# Add ping info to master.csv
python2 extra_ping_info.py $DATA_PATH/master.csv group


# Merge stats with master.csv
python2 merge_runs_to_single_master.py $DATA_PATH/master.csv ${GLOBAL_BASE}_run_*.csv 



# Use pings to "check" if VM is responsive or not - but pings are not 100% trustable
# We cannot start from VM1 since it is used as the trigger for recovery and hence it will always indicate no recovery for VM 1 (ping stops before migration)
for (( vm=1; vm<=$N_VMS; vm++ )); do
   python2 common/ping_recovery_detector.py $DATA_PATH/  joined.csv PING_PATH_L2 $vm
done

# When available, use SSH logs to verify VM state after a run
for (( vm=1; vm<=$N_VMS; vm++ )); do
   python2 common/ssh_recovery_detector.py $DATA_PATH/  joined.csv RESPONSIVE_PATH$vm $vm
done

# Check the 2nd solr run to double-check if solr started after migration or not
for (( vm=1; vm<=$N_VMS; vm++ )); do
   python2 stats_2nd_run.py $DATA_PATH/  joined.csv CSV_PATH${vm}v $vm
done

# Clean temporary run CSV files
PER_RUN_TMPFILE=stats_$(basename $DATA_PATH)_run_*.csv
for f in $PER_RUN_TMPFILE; do 
   rm $f
done

# Calculate per-run VM statistics
python2 multivm_run_stats.py joined.csv $N_VMS

# Filter invalid runs
python2 filter_invalid_runs.py joined.csv

#mv joined.csv.csv ${DATA_PATH}/../csvs/$(basename $DATA_PATH).csv
#mv joined_filtered.csv ${DATA_PATH}/../csvs/$(basename $DATA_PATH).csv
