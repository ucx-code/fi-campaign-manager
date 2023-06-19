import pandas as pd
import time
import sys
import pyping
import signal

def signal_handler(sig, frame):
	df.to_csv(out_path)
	sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

if len(sys.argv) != 5:
	print("Unexpected amount of args")
else:
	host = sys.argv[1]
	L2_LIST = host.split(",")
	interval = float(sys.argv[2])
	retry_count = int(sys.argv[3])
	out_path = sys.argv[4]

	signal.signal(signal.SIGINT, signal_handler)
	df = pd.DataFrame()
	timeout_count = 0
	req_id = 0
	while (timeout_count < retry_count):
		check_flag=0
		for ip in L2_LIST:
			resp = pyping.ping(hostname=ip, timeout=500, count=1)
			req_ts = time.time()
			if (resp.ret_code == 0):
				check_flag += 1
			else:
				print("Unexpected timeout count L2 " + str(timeout_count))

			df = df.append({
				"ts" : req_ts,
				"req_id" : req_id,
				"interval" : interval,
				"retry_count" : retry_count,
				"ret_code" : resp.ret_code,
				"timeout_count" : timeout_count,
				"hostname" : ip,
				
			}, ignore_index=True)
		
		if(check_flag != len(L2_LIST)): #Se a flag for diferente do numero de L2's e sinal que alguma falhou
			timeout_count = timeout_count + 1
		else:
			timeout_count=0

		time.sleep(interval)
		req_id = req_id + 1
		
	df.to_csv(out_path)
	sys.exit(255)
