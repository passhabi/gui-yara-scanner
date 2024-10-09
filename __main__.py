from modules.scanner import YaraScanner
from modules.concurrently import RunWithSysCheck

# from lib.system_check import
from pathlib import Path
import os
import time
# import logging

if __name__ == "__main__":
    # logging.basicConfig(filename='log.txt', level=logging.INFO)
    
    directory = Path("C:/Program Files/Git/")
    rule_path = Path("./rules.yar")

    scanner = YaraScanner(directory, rule_path, console_print=False)
    
    pid = os.getpid() # get process id of the program.
    run_with_syscheck = RunWithSysCheck(scanner, pid)
        
    print(run_with_syscheck.start_benchmark_time())