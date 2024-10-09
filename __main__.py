from modules.scanner import YaraScanner
from modules.concurrently import RunWithSysCheck

# from lib.system_check import
from pathlib import Path
import asyncio
import os
import threading
import time
# import logging

if __name__ == "__main__":
    # logging.basicConfig(filename='log.txt', level=logging.INFO)
    directory = Path(os.path.expanduser("~"))
    rule_path = Path("./rules.yar")
    scanner = YaraScanner(directory, rule_path)
    scanner.start()
    
    # run_with_syscheck = RunWithSysCheck()

    # todo: get info about hardware and how much we can use it!
    # run_with_syscheck.get_system_info()
    
    # # Run monitioring on sperate thread:
    # th_run_with_syscheck = threading.Thread(
    #     target=run_with_syscheck.run_func,
    #     args=(
    #         os.getpid(),  # pid of the main
    #         scanner.start_scan,  # send function to run with threadpoolexcuter.
    #     ),
    #     name="RunTaskMonitoring",
    # )
    # th_run_with_syscheck.start()

    # th_run_with_syscheck.join()

    # import subprocess

    # powershell_command = "& {Start-Process python monkeytest.py -Verb RunAs}"
    # subprocess.run(["powershell", "-Command", powershell_command])

    # monkeytest.start_benchmark()INFO:modules.system_check:CPU Usage: 59.2%  RAM Usage is: 60.0% of the total 2.36 GBINFO:modules.system_check:CPU Usage: 7.8%  RAM Usage is: 60.9% of the total 2.31 GB
