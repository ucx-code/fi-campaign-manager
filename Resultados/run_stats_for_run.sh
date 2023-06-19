# Calc stats for all 6 VMs of a run
SCRIPT_PATH="/root/bernardo/Resultados"


DATA_PATH=$1
RUN_ID=$2
N_VMS=$3

GLOBAL_FILE=stats_$(basename $1)_run_${RUN_ID}.csv
rm $GLOBAL_FILE
for (( vm=1; vm<=$N_VMS; vm++ )); do
   for f in $1/dg${vm}_${RUN_ID}_*.csv; do 
      echo "$1 /dg ${vm}_ ${RUN_ID}_ $f"
      echo "v: $vm"
      if [ $vm = 1 ]; then
         echo "if sem -a"
         python2 ${SCRIPT_PATH}/stats.py -d $f -m $GLOBAL_FILE -r $f -k vm${vm} 
      else
         echo "If com -a"
         python2 ${SCRIPT_PATH}/stats.py -d $f -m $GLOBAL_FILE -r $f -k vm${vm} -a
      fi
   done
done