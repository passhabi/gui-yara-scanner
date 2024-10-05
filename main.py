from lib.scanner import YaraScanner
# from lib.system_check import 
from pathlib import Path
import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
import lib.monkeytest as monkeytest

if __name__ == "__main__":
    # directory = Path(os.path.expanduser("~"))
    # rule_path = Path('./rules.yar')
    
    # ThreadPoolExecutor.submit()
        
    # print(f'\33[32m scanning {directory} ...\33[30m ')
    # scanner = YaraScanner(directory, rule_path)
    # asyncio.run(scanner.scan_directory())
    
    
    import subprocess

    powershell_command = "& {Start-Process python monkeytest.py -Verb RunAs}"
    subprocess.run(["powershell", "-Command", powershell_command])

    monkeytest.start_benchmark()