#!/usr/bin/python
import sys
import paramiko
import os
import yaml
import datetime
import time
import random
import subprocess
import signal
import glob
import shutil
import pandas as pd
import io
import re
import socket



with open('conf.yaml') as f:
    config = yaml.safe_load(f)

#CONFIG PARAMETERS
RESULTS_FILE = str(config['RESULTS_FILE'])
#IPS & DOMAINS
L1A_IP = config['L1A_IP']
L1B_IP = config['L1B_IP']
L0_IP = config['L0_IP']

L1A_DOMNAME = config['L1A_DOMNAME']
L1B_DOMNAME = config['L1B_DOMNAME']

L2_IP = config['L2_IP']

NFS_IP = config['NFS'] #capri

#MACHINE_PATHS
NFS_PATH = config['NFS_PATH']
L1A_IMAGE = config['L1A_IMAGE']
L1B_IMAGE = config['L1B_IMAGE']
PATH_ALLOCATION_FILES = config['PATH_ALLOCATION_FILES']   
L2_IMAGE = config['L2_IMAGE']
SAVE_FILE = config['SAVE_FILE']
RESULTS_PATH = str(config['RESULTS_PATH'])
XEN_PREPROCESSED_FILES = str(config['XEN_PREPROCESSED_FILES'])
HANG_FILES = str(config['HANG_KERNEL_MODULE'])
LAUNCH_CRASH_OUT = str(config['LAUNCH_CRASH_OUT'])
#CRASH DETECTOR VARIABLES
CD_INTERVAL = str(config['CD_INTERVAL'])
CD_RETRY_COUNT = str(config['CD_RETRY_COUNT'])

#SSH DEFINITIONS
USER = config['USER']

#MIGRATION
L0_FLOW_GROUP = config['L0_FLOW_GROUP']


#=============SW FAULTS==============
PATCHES_FOLDER = str(config['PATCHES_FOLDER'])
LAST_PATCH = str(config['LAST_PATCH'])
VMI_TARGET_FILE = str(config['VMI_TARGET_FILE'])
XEN_FOLDER = str(config['XEN_FOLDER'])
VMI_SW_HELPER = str(config['VMI_SW_HELPER'])
#===========WORKLOAD=================

NCLIENTS = str(config['NCLIENTS'])
CLIENT_WAITTIME = str(config['CLIENT_WAITTIME'])
END_TIME_HW = str(config['END_TIME_HW'])
END_TIME_SW = str(config['END_TIME_SW'])
END_TIME_VERIFY = str(config['END_TIME_VERIFY'])
INJ_SLEEP_MIN = config['INJ_SLEEP_MIN'] 
INJ_SLEEP_MAX = config['INJ_SLEEP_MAX']

#==========Define ssh connections========
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

#parameters
VM_NUM = int(sys.argv[1])
FI_TYPE = str(sys.argv[2])

if FI_TYPE == "crash" or FI_TYPE == "hang":
    TARGET =  str(sys.argv[3])
    EXP_NUM = int(sys.argv[4])
else:
    EXP_NUM = int(sys.argv[3])

MIGRATION_SLEEP_TIME=50
RESULTS_DICT = {}

def main():
    PATCH_NR = 0
    global RESULTS_DICT
    TMP_RESULTS=[]
    L2_LIST = []
    PING_PROCESSES={}
    WL_PROCESSES={}
    print("The number of vm is: " + str(VM_NUM))
    print("FI_TYPE: "+ str(FI_TYPE))
    print("EXP_NUM: "+ str(EXP_NUM))

    
    if (FI_TYPE != "sw" and FI_TYPE != 'hw' and FI_TYPE != 'crash' and FI_TYPE != 'hang'):
        print("2nd argument must be sw, hw, crash, or hang")
        sys.exit(1)

    

    if not os.path.exists(RESULTS_PATH):
        os.makedirs(RESULTS_PATH)

    for i in range(VM_NUM):
        if(i<6):
            L2_LIST.append(L2_IP+'10'+str(i+4))
        else:
            L2_LIST.append(L2_IP+'1'+str(i+4))
    
    

    #------------------- RESULTS ------------------------
    #cria ficheiro
    df = pd.DataFrame()
    df.to_csv(RESULTS_FILE, index=False)
    
    
    #------------- SW FAULT PATCHES ---------------------

    if(FI_TYPE=="sw"):
        #Get all .patch in patches folder
        ALL_PATCHES =  glob.glob(PATCHES_FOLDER + '/*.patch') or [PATCHES_FOLDER + '/*.patch'] #[]-> cria se nao existir
        if os.path.isfile(LAST_PATCH):
            with open(LAST_PATCH, 'r') as f:
                PATCH_NR = int(f.read().strip())
        else: #Se nao existir
            PATCH_NR = 0
            with open(LAST_PATCH, 'w') as f:
                f.write(str(PATCH_NR))
      
    command = ["cd /var/lib/nova/instances/nestedvirt/new_image; rm *-snap.qcow2; qemu-img create -f qcow2 -b debian-disk.qcow2 debian-disk-snap.qcow2; qemu-img create -f qcow2 -b debian-disk2.qcow2 debian-disk2-snap.qcow2;"]
    ssh_call(L0_IP,USER,command)

    
    #-----------------------------------------------------
    for i in range(EXP_NUM):

   
        START = int(time.mktime(datetime.datetime.now().timetuple()) * 1000)
        RESULTS_DICT["START"] = START
        command=['/root/print_rdtsc']
        output = ssh_call(L0_IP,USER,command)
        RESULTS_DICT["START_L0_RDTSC"] = str(output.rstrip())
        print("START_L0_RDTSC: " + str(output))

        if(FI_TYPE=='hw'):          #Generate fault for HW
            hw_fault_generator()
        elif(FI_TYPE=='sw'):
            try:
                PATCH_FILE = ALL_PATCHES[PATCH_NR]
            except IndexError:
                print('No more patch to be done')
                sys.exit(1) 
            RESULTS_DICT["PATCH_NR"] = PATCH_NR
            print("Patch chosen")

        launch_L1s()
        if(FI_TYPE=='sw'):
            ssh_retry()
            xen_preprocessed_files(PATCH_FILE)
    
            if not patch_xen_fault(PATCH_FILE):
                print("Next Injection")
                PATCH_NR +=1
                with open(LAST_PATCH, 'w') as f:
                    f.write(str(PATCH_NR))
                    print("New patch after failure incoming...")
                continue
            
            print("DONE PATCH")
     
    
            TMP_RESULTS = extract_offsets()
            RESULTS_DICT["VMI_ENABLEFI_ADDR"] = str(TMP_RESULTS[0])
            RESULTS_DICT["VMI_INJTSC_ADDR"] = str(TMP_RESULTS[1])
            RESULTS_DICT["VMI_ITERSBEFORE_ADDR"] = str(TMP_RESULTS[2])
            RESULTS_DICT["VMI_ITERSAFTER_ADDR"] = str(TMP_RESULTS[3])
            RESULTS_DICT["VMI_DOMAINLIST_ADDR"] = str(TMP_RESULTS[4])
            
            print("Enable FI offset is: " + str(RESULTS_DICT["VMI_ENABLEFI_ADDR"]))
            print("Inj. TSC offset is: " + str(RESULTS_DICT["VMI_INJTSC_ADDR"]))
            print("Iters before offset is: " + str(RESULTS_DICT["VMI_ITERSBEFORE_ADDR"]))
            print("Iters after offset is: " + str(RESULTS_DICT["VMI_ITERSAFTER_ADDR"]))
            print("Domain list offset is: " + str(RESULTS_DICT["VMI_DOMAINLIST_ADDR"]))
        
            print("sleeping 30s")
            time.sleep(30)
            launch_L1s_sw()
    
      
        ssh_retry() #Wait for L1's to start
        get_domid()    

        memory_allocation()
        spawn_L2()
        start_L2(L2_LIST) #wait for L2 to start and start solr service
        create_save_file()
        launch_monitors(PING_PROCESSES)

        PING_L2_PROCESSES = launching_crashing_point(L2_LIST) #LAUNCHING CRASH POINTS

        if(FI_TYPE == 'hw' or FI_TYPE == 'crash'or FI_TYPE == 'hang'):
            start_workload(WL_PROCESSES,L2_LIST,END_TIME_HW)
        elif(FI_TYPE == 'sw'):
             start_workload(WL_PROCESSES,L2_LIST,END_TIME_SW)

        if(FI_TYPE=='hw'):          #Inject fault
            inject_fault_hw()
        elif(FI_TYPE == 'sw'):
            inject_fault_sw(RESULTS_DICT["VMI_ENABLEFI_ADDR"])
        elif(FI_TYPE == 'crash'):
            inject_crash(L2_LIST,TARGET)
        elif(FI_TYPE == 'hang'):
            inject_hang(L2_LIST,TARGET)

            
        wl_processes_wait(WL_PROCESSES)
        verify_vm_state(L2_LIST)
        verify_correctness(L2_LIST)
        stop_monitors(PING_PROCESSES, PING_L2_PROCESSES) #Kill processes

        if(FI_TYPE=='sw'):
            extract_sw_stats_vmi()

        if (FI_TYPE=='hw'):
            FI_CSV = extract_dmesg()  #extract dmesg
        else:
            FI_CSV= None
        REBOOT_START = extract_results(START,i,L2_LIST)
        print("REBOOT_START: " + str(REBOOT_START))
        REBOOT_DUR, PATCH_NR = restore_snapshots(REBOOT_START, PATCH_NR)
        
        PING_L2_PROCESSES =0
        df = store_results(df,FI_CSV)
        RESULTS_DICT.clear()
 
#--------------------------------------General Functions---------------------------------------

#***************LAUNCH L1'S***********************
def launch_L1s(): 
    print("Launching L1s in (L0)")

    #Destroy L1A & L1B
    commands= [
        'xl destroy ' + L1A_DOMNAME,
        'xl destroy ' + L1B_DOMNAME,
        'mount -o hard,noacl,nocto,noatime,nodiratime ' + NFS_IP + ':' + NFS_PATH,
        'xl create ' +  L1A_IMAGE,
        'xl create ' +  L1B_IMAGE,
        
    ]
    
    ssh_call(L0_IP,USER,commands)
    if(FI_TYPE=='hw' or FI_TYPE == 'crash'):
        command=['/root/print_rdtsc']
        output = ssh_call(L0_IP,USER,command)
        RESULTS_DICT["l0_rdtsc"] = output
        DOLMA_TSC = int(time.mktime(datetime.datetime.now().timetuple()) * 1000)
        RESULTS_DICT["dolma_tsc"] = str(DOLMA_TSC)

#******************Get ids from L1A_ID, L1B_ID*********************
def get_domid():
    global L1A_ID, L1B_ID
    commands = [
        'xl domid ' + L1A_DOMNAME,
        'xl domid ' + L1B_DOMNAME,
    ]
    result = ssh_call(L0_IP,USER,commands)
    L1A_ID, L1B_ID = result.splitlines()


#*********************Check connection with L1A & L1B*****************
def ssh_retry():
    print("Wait for L1A & L1B to start")
    LAUNCH_L1_START = int(time.mktime(datetime.datetime.now().timetuple()) * 1000)
    command = "bash ssh-retry.sh " + USER + '@'+L1A_IP + " pwd &>/dev/null"
    subprocess.call(["bash", "-c", command])
    
    commandB = "bash ssh-retry.sh " + USER + '@'+L1B_IP + " pwd &>/dev/null"
    subprocess.call(["bash", "-c", commandB])
    LAUNCH_L1_END= int(time.mktime(datetime.datetime.now().timetuple()) * 1000)
    LAUNCH_L1_DUR= LAUNCH_L1_END - LAUNCH_L1_START
    RESULTS_DICT['l1_launch']  = LAUNCH_L1_DUR
    print("Retry complete")


#**********************Memory allocation in L1B******************************
def memory_allocation():

    commands=[
        'bash alloc.sh',
    ]
    ssh_call(L1B_IP,USER,commands)
    print("Memory allocation completed")


#*****************************Create L2's******************************
def spawn_L2():
    print("Spawn L2's")
    commands=[
        'mount -o noacl,nocto,noatime,nodiratime,nolock ' + NFS_IP+':' + NFS_PATH,
    ]
    
    for i in range(VM_NUM):
        commands.append('xl create '+ L2_IMAGE + str(i+2)+'.cfg') 
        ssh_call(L1A_IP,USER,commands)
    
        commands=[]
        print("sleep (55)...")
        time.sleep(55) 
        print("Waking up...")
        commands.append('xl save-nvmcs 1 '+ str(i+1) )         
        commands.append('bash ' + '/root/wait_for_nvmcs.sh '+ str(i+1))
        ssh_call(L0_IP,USER,commands)
        print(str(i+1)+ " done")
        commands=[]
    
    print("L2 spawned and ready")


#********************************Check connection in L2'S**********************
def start_L2(L2_LIST):
    print("Waiting for SSH in L2's")
    processes = []
    print("Startin solr...")
    for i in range(VM_NUM):
        print("VM_NUM: " + str(i))
        command = 'bash ssh-retry.sh ' + USER+'@'+ L2_LIST[i] + ' true' + " pwd &>/dev/null"
        subprocess.call(["bash", "-c", command])
        solr_start = subprocess.Popen(['ssh', USER+'@'+L2_LIST[i], 'service solr restart', '&'])
        processes.append(solr_start)
    print("Solr started...")
    # Wait for all processes to complete
    for process in processes:
        process.wait()


#****************************Create save file of L2's************************
def create_save_file():
    time.sleep(5)
    CREATE_BASE_SAVE_START = int(time.mktime(datetime.datetime.now().timetuple()) * 1000)
    RESULTS_DICT["base_save_start"] = str(CREATE_BASE_SAVE_START)
    print("Creating base save file started: "+ str(CREATE_BASE_SAVE_START))
    commands=[]
    for i in range(VM_NUM):
        commands.append(SAVE_FILE+ str(i+1) + ' bash create_savefile.sh ' + str(i+1) + ' /tmp/save.tmp '+ " pwd &>/dev/null; " + 'rm /tmp/save.tmp; sleep 5;')
    ssh_call(L1A_IP,USER,commands)


    CREATE_BASE_SAVE_END = int(time.mktime(datetime.datetime.now().timetuple()) * 1000)
    CREATE_BASE_SAVE_DUR = (CREATE_BASE_SAVE_END - CREATE_BASE_SAVE_START)
    RESULTS_DICT["base_save_end"] = str(CREATE_BASE_SAVE_END)
    RESULTS_DICT["create_base"] = CREATE_BASE_SAVE_DUR
    
    print("Creating base save file took " + str(CREATE_BASE_SAVE_DUR))
    print("Creating base save file ended " + str(CREATE_BASE_SAVE_END))


#*****************************Launch monitors for L1's& L0*******************
def launch_monitors(PING_PROCESSES):
    print("Launch monitors for L1A, L1B & L0")
    pingL1A = "ping_L1A_process"
    pingL1B = "ping_L1B_process"
    pingL0 = "ping_L0_process"

    PING_PROCESSES[pingL1A] = subprocess.Popen(["python", "crash_detector.py", L1A_IP, CD_INTERVAL, CD_RETRY_COUNT,  os.path.join(RESULTS_PATH, "ping_{}.csv".format(L1A_IP))])
    PING_PROCESSES[pingL1B] = subprocess.Popen(["python", "crash_detector.py", L1B_IP, CD_INTERVAL, CD_RETRY_COUNT,  os.path.join(RESULTS_PATH, "ping_{}.csv".format(L1B_IP))])
    PING_PROCESSES[pingL0] = subprocess.Popen( ["python", "crash_detector.py",  L0_IP,  CD_INTERVAL, CD_RETRY_COUNT, os.path.join(RESULTS_PATH, "ping_{}.csv".format(L0_IP))])
     

    return PING_PROCESSES

#************************Launch crashing points for L2's (Observation Point)******************
def launching_crashing_point(L2_LIST):
    print("Crashing points")

    with open(LAUNCH_CRASH_OUT, "w") as f:
        PING_L2_PROCESSES = subprocess.Popen( ["bash", "launch_crash_detector_for_group.sh", ",".join(L2_LIST), str(L0_FLOW_GROUP), str(L1A_ID), str(L1B_ID), str(L1B_IP), str(VM_NUM)],preexec_fn=os.setsid,stdout=f) #
   
    
    print("Crashing points done!!")

    return PING_L2_PROCESSES


#***************************Start Workload in L2's*************************
def start_workload(WL_PROCESSES, L2_LIST, END_TIME):
    WL_TSTAMP = int(time.mktime(datetime.datetime.now().timetuple()) * 1000)
    print("Start workload: "+ str(WL_TSTAMP))
    RESULTS_DICT["wl_tstamp"] = WL_TSTAMP
    for i,ip in enumerate(L2_LIST):
        key = "WL_PID"+str(i+1)
        WL_PROCESSES[key] = subprocess.Popen(["python", "client_by_time.py", ip, NCLIENTS, CLIENT_WAITTIME, END_TIME, os.path.join(RESULTS_PATH, "dg{}.csv".format(i+1))])
    
    print("Workload started")
    return WL_PROCESSES

#***********************Wait for the end of workload processes***************
def wl_processes_wait(WL_PROCESSES):
    print("Wait for the end of WL_PROCESSES")
    for i in range(len(WL_PROCESSES)):
        key = "WL_PID" + str(i+1)
        process = WL_PROCESSES[key]
        process.wait()
    
    print("Workload Processes ended!")

#*************************Verify vm state*********************
def verify_vm_state(L2_LIST):
    processes_wait= []
    for i, ip in enumerate(L2_LIST):
        process = subprocess.Popen(["python", "client_by_time.py", ip, NCLIENTS, CLIENT_WAITTIME, END_TIME_VERIFY, os.path.join(RESULTS_PATH, "dgv{}.csv".format(i+1))])
        processes_wait.append(process)
    
    for process in processes_wait:
        process.wait()

#******************************Verifica sistema operativo*******************
def verify_correctness(L2_LIST):
    processes_wait = []
    for i, ip in enumerate(L2_LIST):
        command = 'timeout 120 ssh -o ConnectTimeout=60 root@' + ip + ' " pwd; dmesg; date +%s; "' + " &> " + os.path.join(RESULTS_PATH, "responsive" + str(i+1) + '.txt')

        process = subprocess.Popen(command, shell=True)
        processes_wait.append(process)
    
    for process in processes_wait:
        process.wait()

#***********************Kill monitors processes********************
def stop_monitors(PING_PROCESSES, PING_L2_PROCESSES):
    print("Kill processes")
    for process in PING_PROCESSES.values():
        process.send_signal(signal.SIGINT)

    PING_PROCESSES.clear()

    # Send the SIGINT signal to all processes in the process group
    # Read the subprocess stdout
 
    CRSH_DET_PID = PING_L2_PROCESSES.pid
    os.killpg(CRSH_DET_PID, signal.SIGINT)

    print("==========Processes Killed==========")


def ssh_call(ip,user,commands_list):
    command = '\n'.join(commands_list)

    ssh.connect(str(ip),username=user)

    if ssh.get_transport().is_active():
        stdin, stdout, stderr = ssh.exec_command(str(command))
        stdout_result, stderr_result = stdout.read().decode(), stderr.read().decode()
        if stderr_result:
            print(stderr_result) 

        ssh.close()
        return stdout_result

    else:
        print("Error: Connection to {} failed".format(ip))

#TO CRASH
def ssh_call_crash(ip,user,commands_list):
    command = '\n'.join(commands_list)

    ssh.connect(str(ip),username=user)

    if ssh.get_transport().is_active():
        try:
            stdin, stdout, stderr = ssh.exec_command(str(command), timeout=10)
            stdout_result, stderr_result = stdout.read().decode(), stderr.read().decode()
            if stderr_result:
                print(stderr_result) 
        except socket.timeout:
            print("[Crash&Hang] SSH connection closed")
            stdout_result, stderr_result = "", ""
        finally:
            ssh.close()
        return stdout_result

    else:
        print("Error: Connection to {} failed".format(ip))
        
def extract_dmesg():
    print("Extracting dmesg")
    commands = [
        'xl dmesg | tail -n100',
    ]
    DMESG_LOG = ssh_call(L0_IP,USER,commands)
    command = ['python', 'extract_fi_log.py', DMESG_LOG] 

    result = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = result.communicate()
    if result.returncode == 0:
        FI_CSV = output.decode('utf-8').strip()
        
    else:
        error_message = error.decode('utf-8').strip()
        print("Failed to extract FI CSV: ", error_message)

    
    return FI_CSV

def extract_results(START,EXP,L2_LIST):
    

    print("Rebooting L0")
    commands = [
        'sleep 5; reboot',
    ]
    ssh_call(L0_IP, USER, commands)
    REBOOT_START = int(time.mktime(datetime.datetime.now().timetuple()) * 1000)
 

    for i in range(VM_NUM):
        src_file = RESULTS_PATH + "/dg" + str(i+1) + ".csv"
        new_name = 'dg' + str(i+1) + '_'+ str(EXP) + '_' + str(START) + '.csv'
        RESULTS_DICT['CSV_PATH' + str(i+1)] = new_name
        dst_file = RESULTS_PATH +'/' + new_name
        shutil.move(src_file, dst_file)

        src_filev = RESULTS_PATH + "/dgv" + str(i+1) + ".csv"
        new_name= 'dgv' + str(i+1) + '_' + str(EXP) + '_' + str(START)+'.csv'
        RESULTS_DICT['CSV_PATH' + str(i+1) + 'v'] = new_name
        dst_filev = RESULTS_PATH + '/' + new_name
        shutil.move(src_filev, dst_filev)

        src_file_resp = RESULTS_PATH + "/responsive" + str(i+1) + '.txt'
        new_name= "responsive" + str(i+1) + '_' + str(EXP) + '_' + str(START) + '.txt'
        RESULTS_DICT['RESPONSIVE_PATH' + str(i+1)] = new_name
        dst_file_resp = RESULTS_PATH + "/" + new_name
        shutil.move(src_file_resp, dst_file_resp)
    
    #PINGS

    src_file_L0 = RESULTS_PATH + "/" + "ping_" + L0_IP + '.csv'
    new_name = 'ping_' + str(EXP) + '_' + L0_IP + '_' + str(START) + '.csv'
    RESULTS_DICT['PING_PATH_L0'] = new_name
    dst_file_L0 = RESULTS_PATH + '/' + new_name
    shutil.move(src_file_L0,dst_file_L0)

    src_file_L1A = RESULTS_PATH + "/" + "ping_" + L1A_IP + '.csv'
    new_name = 'ping_' + str(EXP) + '_' + L1A_IP + '_' + str(START) + '.csv'
    RESULTS_DICT['PING_PATH_L1A'] = new_name
    dst_file_L1A = RESULTS_PATH + '/' + new_name
    shutil.move(src_file_L1A,dst_file_L1A)

    src_file_L1B = RESULTS_PATH + "/" + "ping_" + L1B_IP + '.csv'
    new_name='ping_' + str(EXP) + '_' + L1B_IP + '_' + str(START) + '.csv'
    RESULTS_DICT['PING_PATH_L1B'] = new_name
    dst_file_L1B = RESULTS_PATH + '/' + new_name
    shutil.move(src_file_L1B,dst_file_L1B)

    src_file_L2 = "ping_L2.csv"
    print("src_file_L2: " + src_file_L2)
    new_name = 'ping_L2_' + str(EXP) + '_' + str(START) + '.csv'
    RESULTS_DICT['PING_PATH_L2'] = new_name
    dst_file_L2 = RESULTS_PATH + '/' + new_name
    shutil.move(src_file_L2,dst_file_L2) 

    print("Results extraction ended")
    return REBOOT_START

def restore_snapshots(REBOOT_START, PATCH_NR):
    print("Restoring snapshots")
    commands = [
        "bash redo_snapshots.sh",
        "rm /root/nfs/centos-big-l2-snapg*; cd /root/nfs;  qemu-img create -f qcow2 -b centos-big-l2-g2.qcow2 centos-big-l2-snapg2.qcow2; qemu-img create -f qcow2 -b centos-big-l2-g3.qcow2 centos-big-l2-snapg3.qcow2; qemu-img create -f qcow2 -b centos-big-l2-g4.qcow2 centos-big-l2-snapg4.qcow2; qemu-img create -f qcow2 -b centos-big-l2-g5.qcow2 centos-big-l2-snapg5.qcow2; chown nobody:nobody *;",

    ]
    ssh_call(NFS_IP,USER,commands)
    print("ssh_retry to L0")

    command = "bash ssh-retry.sh " + USER + '@'+L0_IP + " true"
    subprocess.call(["bash", "-c", command])
    print("SSH-RETRY DONE")
    REBOOT_END = int(time.mktime(datetime.datetime.now().timetuple()) * 1000)
    RESULTS_DICT["REBOOT_END"] = REBOOT_END
    REBOOT_DUR = REBOOT_END - REBOOT_START
    RESULTS_DICT["REBOOT_DUR"] = str(REBOOT_DUR)
    print("Reboot took " + str(REBOOT_DUR))
    time.sleep(5)

    commands = [
            "rm /root/nfs/centos-big-l2-snapg*; cd /root/nfs;  qemu-img create -f qcow2 -b centos-big-l2-g2.qcow2 centos-big-l2-snapg2.qcow2; qemu-img create -f qcow2 -b centos-big-l2-g3.qcow2 centos-big-l2-snapg3.qcow2; qemu-img create -f qcow2 -b centos-big-l2-g4.qcow2 centos-big-l2-snapg4.qcow2; qemu-img create -f qcow2 -b centos-big-l2-g5.qcow2 centos-big-l2-snapg5.qcow2; chown nobody:nobody *;",
    ]
    ssh_call(NFS_IP,USER,commands)

   
    if (FI_TYPE== "sw"):
        PATCH_NR +=1
        with open(LAST_PATCH, 'w') as f:
            f.write(str(PATCH_NR))

    return REBOOT_DUR, PATCH_NR


def store_results(df,FI_CSV):
    print("storing results...")
    
    with open(LAUNCH_CRASH_OUT, "r+") as f:
        output = f.read()
        print("output: " + output)
    crash_tstamp_match = re.search(r"Crash detected @ (\d+)", output)
    if crash_tstamp_match:
        print("crash detected")
        RESULTS_DICT["crash_tstamp"] = int(crash_tstamp_match.group(1))

    flow_migration_dur_match = re.search(r"Flow\.sh migration took (\d+)", output)
    if flow_migration_dur_match:
        RESULTS_DICT["flow_migration"] = int(flow_migration_dur_match.group(1))

    restore_dur_match = re.search(r"Restore took (\d+)", output)
    if restore_dur_match:
        RESULTS_DICT["restore"] = int(restore_dur_match.group(1))
    
     

    if(FI_TYPE=="hw"):
        df_fi = pd.read_csv(pd.compat.StringIO(FI_CSV), header=None, names=["fi_tsc", "fi_rip", "fi_rbp", "fi_rsp", "fi_rax", "fi_rbx", "fi_rcx", "fi_rdx", "fi_r8", "fi_r9", "fi_r10", "fi_r11", "fi_r12", "fi_r13", "fi_r14", "fi_r15"])
        row_values = df_fi.iloc[0].tolist()
        dict_fi = {col_name: value for col_name, value in zip(df_fi.columns, row_values)}
        RESULTS_DICT.update(dict_fi)

    df = df.append(RESULTS_DICT, ignore_index=True)
    df.to_csv(RESULTS_FILE, index=False)
    print("======Injection ended======")
    return df




#----------------------------------------Hardware Functions---------------------------------------

#***********************Generate HW fault*******************
def hw_fault_generator():
    global INJ_REG, INJ_BIT, INJ_SLEEP
    INJ_REG = random.randint(0,14) #For HW between [0,14]
    INJ_BIT = random.randint(0,63) #Bit for injection
    INJ_SLEEP = round(random.uniform( INJ_SLEEP_MIN / 1000, INJ_SLEEP_MAX / 1000), 3)
    print("INJ_REG: " + str(INJ_REG) + " INJ_BIT: " + str(INJ_BIT))
    RESULTS_DICT["INJ_REG"] = INJ_REG
    RESULTS_DICT["INJ_BIT"] = INJ_BIT
    RESULTS_DICT["INJ_SLEEP"] = INJ_SLEEP
    print("Hw fault generated")


#************************Inject fault in HW*****************
def inject_fault_hw():
    print("Sleeping the inj_sleep time " + str(INJ_SLEEP))
    time.sleep(INJ_SLEEP)
    FI_TSTAMP = int(time.mktime(datetime.datetime.now().timetuple()) * 1000)
    print("Injecting fault in timestamp: "+ str(FI_TSTAMP))
    RESULTS_DICT["fi_tstamp"] = FI_TSTAMP
    commands=[
        'xl inject-fault ' + str(L1A_ID) + ' ' + str(INJ_BIT) + ' ' + str(INJ_REG)
    ]
    ssh_call(L0_IP,USER,commands)
    print("Fault Injected")
    

#----------------------------------------Software Functions-------------------------------------------

#*****************************Patch Xen with Fault***********************
def xen_preprocessed_files(PATCH_FILE):
   
    FILE = os.path.splitext(os.path.basename(VMI_TARGET_FILE))[0] + '-handfixed.c'
    NAME_TO_CHANGE = FILE.replace('-handfixed', '')
    DESTINATION = os.path.dirname(VMI_TARGET_FILE)
    TO_COPY =  XEN_PREPROCESSED_FILES + '/' + FILE

 


    commands=[
        'mount -o noacl,nocto,noatime,nodiratime,nolock ' + NFS_IP+':' + NFS_PATH,
        "rm " + VMI_TARGET_FILE,
        "scp " + TO_COPY + ' ' + DESTINATION,
        "mv " + DESTINATION + '/' + FILE + ' ' + DESTINATION + '/' + NAME_TO_CHANGE,
    ]
    ssh_call(L1A_IP,USER,commands)
    print("pre_processed Done")


def patch_xen_fault(PATCH_FILE):
    
    command = ['scp', PATCH_FILE, USER + "@" + L1A_IP + ":/tmp"]
    result = subprocess.call(command)

    # Check the result of the command
    if result == 0:
        print("File copied successfully")
    else:
        print("Error: " + str(result))
        
    PATCH_FILE_BASE = os.path.basename(PATCH_FILE)  #Get the file name
    VMI_TARGET_FOLDER = os.path.dirname(VMI_TARGET_FILE)
    RESULTS_DICT['PATCH_FILE'] = str(PATCH_FILE_BASE)

    commands = ['cd ' + VMI_TARGET_FOLDER + '; patch --quiet < /tmp/'+PATCH_FILE_BASE,
               ]


    ssh_call(L1A_IP,USER,commands)

   
    commands = [    '(cd ' + XEN_FOLDER + ' && rm -f var_list && make -j6 dist) &> /dev/null; echo $?', 
                ]
 

    MAKE_DIST_RET = int(ssh_call(L1A_IP,USER,commands))
    print("MAKE_DIST_RET: " + str(MAKE_DIST_RET))

    if(MAKE_DIST_RET != 0):
        print("Make failed")
        return False    #FALSE FAILED -> CANCEL EXPERIMENT

    commands = [
        '(cd ' + XEN_FOLDER + ' && make -j4 install) &> /dev/null; echo $?'
    ]
    MAKE_INST_RET = int(ssh_call(L1A_IP,USER,commands))
    print("MAKE_INST_RET: " + str(MAKE_INST_RET))
    if (MAKE_INST_RET != 0 ):
        print("Make failed")
        return False    #FALSE FAILED -> CANCEL EXPERIMENT

    print("No FAILS LETS GO")
    return True
 

def extract_offsets():

    commands = ['/sbin/ldconfig; sync; (cd ' + XEN_FOLDER + ' && bash extract_offsets.sh)',

                ]
    for c in commands:
        print("command: " + str(c))
    ssh_call(L1A_IP,USER,commands)
    
    command = ['scp', USER + "@" + L1A_IP + ":" + XEN_FOLDER + 'var_list', '/tmp/var_list']
    print("command: " + " ".join(command))
    subprocess.call(command)

    commands= [
        'poweroff',
    ]
    ssh_call(L1A_IP,USER,commands)
    print("Poweroff done...")
 




    command = 'echo "ibase=16;$( cat /tmp/var_list | grep " fi_enabled" | awk \'{print toupper($1)}\' | cut -c 3-)" | bc;' \
              'echo "ibase=16;$( cat /tmp/var_list | grep "tsc_on_injection" | awk \'{print toupper($1)}\' | cut -c 3-)" | bc;' \
              'echo "ibase=16;$( cat /tmp/var_list | grep "iters_before" | awk \'{print toupper($1)}\' | cut -c 3-)" | bc;' \
              'echo "ibase=16;$( cat /tmp/var_list | grep "iters_after" | awk \'{print toupper($1)}\' | cut -c 3-)" | bc;' \
              'echo "ibase=16;$( cat /tmp/var_list | grep "domain_list" | awk \'{print toupper($1)}\' | cut -c 3-)" | bc;'


    output = subprocess.check_output(command, shell=True)
    result = output.decode('utf-8').strip()
    

    res_list = result.split('\n')
    command = "rm -f /tmp/var_list;"
    subprocess.call(["bash", "-c", command])
   
    return  res_list

def extract_sw_stats_vmi():
    print("Extracting SW stats with VMI") #Vai a memoria ler valor das variaveis
    time.sleep(20)
    commands = [VMI_SW_HELPER + ' ' + L1A_DOMNAME + ' read_injtsc ' + RESULTS_DICT['VMI_INJTSC_ADDR'],  #Momento exato em que a fault e ativada pela primeira vez
                VMI_SW_HELPER + ' ' + L1A_DOMNAME + ' read_itersafter ' + RESULTS_DICT['VMI_ITERSAFTER_ADDR'], #numero de vezes que passamos na faults depois de estar ativa
                VMI_SW_HELPER + ' ' + L1A_DOMNAME + ' read_itersbefore ' + RESULTS_DICT['VMI_ITERSBEFORE_ADDR'], #numero de vezes que passamos na faults antes de estar ativa
                ]
    for c in commands:
        print("extract: " + str(c))
    result = ssh_call(L0_IP,USER,commands)
    SW_INJTSC, SW_ITERSAFTER, SW_ITERSBEFORE = result.splitlines()

    print("SW_INJTSC: " + str(SW_INJTSC))
    RESULTS_DICT['SW_INJTSC'] = str(SW_INJTSC)

    print("SW_ITERSAFTER: " + str(SW_ITERSAFTER))
    RESULTS_DICT['SW_ITERSAFTER'] = str(SW_ITERSAFTER)

    print("SW_ITERSBEFORE: " + str(SW_ITERSBEFORE))
    RESULTS_DICT['SW_ITERSBEFORE'] = str(SW_ITERSBEFORE)

    
def launch_L1s_sw():
    print("Launching L1s in (L0) - sw")

    #Destroy L1A & L1B
    commands= [
        'xl create ' +  L1A_IMAGE,
        'xl create ' +  L1B_IMAGE,
    ]
    ssh_call(L0_IP,USER,commands)
    
    command=['/root/print_rdtsc']
    output = ssh_call(L0_IP,USER,command)
    RESULTS_DICT["l0_rdtsc"] = output
    DOLMA_TSC = int(time.mktime(datetime.datetime.now().timetuple()) * 1000)
    RESULTS_DICT["dolma_tsc"] = str(DOLMA_TSC)

def inject_fault_sw(VMI_ENABLEFI_ADDR):

    INJ_SLEEP = round(random.uniform( INJ_SLEEP_MIN / 1000, INJ_SLEEP_MAX / 1000), 3)
    print("Injecting fault sleeping... INJ_SLEEP= " + str(INJ_SLEEP))
    RESULTS_DICT["INJ_SLEEP"] = str(INJ_SLEEP)
    time.sleep(INJ_SLEEP)
    
    FI_TSTAMP = int(time.mktime(datetime.datetime.now().timetuple()) * 1000)
    print("Injecting fault in timestamp: "+ str(FI_TSTAMP))
    RESULTS_DICT["fi_tstamp"] = str(FI_TSTAMP)
    commands=[
            VMI_SW_HELPER + ' ' + L1A_DOMNAME + ' set_fi_enabled ' + VMI_ENABLEFI_ADDR
    ]


    for c in commands:
        print("fault injection command: " + c)

    ssh_call(L0_IP, USER, commands)
    print("SW Fault Injected")


#------------------------------------Crash Failure---------------------------------------------------

def inject_crash(L2_LIST,TARGET):
    INJ_SLEEP = round(random.uniform( INJ_SLEEP_MIN / 1000, INJ_SLEEP_MAX / 1000), 3)
    print("Injecting Crash sleeping... INJ_SLEEP= " + str(INJ_SLEEP))
    RESULTS_DICT["INJ_SLEEP"] = INJ_SLEEP

    time.sleep(INJ_SLEEP)

    FI_TSTAMP = int(time.mktime(datetime.datetime.now().timetuple()) * 1000)
    print("Injecting Crash in timestamp: "+ str(FI_TSTAMP))
    RESULTS_DICT["fi_tstamp"] = FI_TSTAMP
    

    if (TARGET == 'L1'):
        TARGET = L1A_ID
        RESULTS_DICT["crash_target"] = str("L1A")
        commands = [
            "echo 1 > /proc/sys/kernel/sysrq",
            'echo "c" > /proc/sysrq-trigger',
        ]


        ssh_call_crash(L1A_IP,USER,commands)
        print("crash injected")
    else:
        TARGET = random.randint(1,VM_NUM) #RANDOM para L2 entre 1 e o numero de VMS que e os IDs
        RESULTS_DICT["crash_target"] = str("L2_" + str(TARGET))
        commands = [
            "echo 1 > /proc/sys/kernel/sysrq",
            'echo "c" > /proc/sysrq-trigger',
        ]

        ssh_call_crash(L2_LIST[TARGET-1],USER,commands)

def inject_hang(L2_LIST,TARGET):
    INJ_SLEEP = round(random.uniform( INJ_SLEEP_MIN / 1000, INJ_SLEEP_MAX / 1000), 3)
    print("Injecting Hang sleeping... INJ_SLEEP= " + str(INJ_SLEEP))
    RESULTS_DICT["INJ_SLEEP"] = INJ_SLEEP

    time.sleep(INJ_SLEEP)

    FI_TSTAMP = int(time.mktime(datetime.datetime.now().timetuple()) * 1000)
    print("Injecting Hang in timestamp: "+ str(FI_TSTAMP))
    RESULTS_DICT["fi_tstamp"] = FI_TSTAMP
    if (TARGET == 'L1'):
        TARGET = L1A_ID
        RESULTS_DICT["hang_target"] = str("L1A")
        commands = [
            "insmod " + HANG_FILES + '/hang.ko',
        ]


        ssh_call_crash(L1A_IP,USER,commands)
        print("hang injected")
    else:
        TARGET = random.randint(1,VM_NUM) #RANDOM para L2 entre 1 e o numero de VMS que e os IDs
        RESULTS_DICT["hang_target"] = str("L2_" + str(TARGET))
        commands = [
            "echo 1 > /proc/sys/kernel/sysrq",
            'echo "c" > /proc/sysrq-trigger',
        ]

        ssh_call_crash(L2_LIST[TARGET-1],USER,commands)


if __name__ == "__main__":
    main()  