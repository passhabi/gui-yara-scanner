from scanner import YaraScanner
from pathlib import Path
import asyncio
import os

if __name__ == "__main__":
    directory = Path(os.path.expanduser("~"))
    rule_path = Path('./rules.yar')
    
    print(f'\33[32m scanning {directory} ...\33[30m ')
    scanner = YaraScanner(directory, rule_path)
    asyncio.run(scanner.scan_directory())