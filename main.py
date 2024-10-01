import os
from pathlib import Path
import yara
import threading
import asyncio

# from concurrent.futures import ThreadPoolExecutor


class YaraScanner:
    def __init__(self, directory, rule_path):
        self.directory = Path(directory)
        self.rule = yara.compile(filepath=str(rule_path), includes=False)

    async def scan_directory(self):
        async with asyncio.TaskGroup() as tg:
            for file_path in self.directory.rglob("*"):
                if file_path.is_file():
                    # print(file_path)
                    tg.create_task(self.scan_file(file_path))

    async def scan_file(self, file_path):
        self.file_path = file_path
        result = self.rule.match(
            str(file_path),
            callback=self.find_match,
            which_callbacks=yara.CALLBACK_MATCHES,
        )

    def find_match(self, data):
        print(f"\33[31m {data['rule']}: {self.file_path}\33[0m")


if __name__ == "__main__":
    directory = Path(os.path.expanduser("~")) / "Desktop"
    rule_path = Path('./rules.yar')
    scanner = YaraScanner(directory, rule_path)
    asyncio.run(scanner.scan_directory())