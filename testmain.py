import os
from pathlib import Path
import yara

class YaraScanner:
    def __init__(self, directory, rule_path):
        self.directory = Path(directory)
        self.rule = yara.compile(filepath=str(rule_path), includes=False)

    def scan_directory(self):
        for file_path in self.directory.rglob("*"):
            if file_path.is_file():
                self.scan_file(file_path)

    def scan_file(self, file_path):
        self.file_path = file_path
        try:
            result = self.rule.match(
                str(file_path),
                callback=self.find_match,
                which_callbacks=yara.CALLBACK_MATCHES,
            )
        except yara.Error:
            print(f"Coudn't read the file {self.file_path}")
            
    def find_match(self, data):
        print(f"\33[31m {data['rule']}: {self.file_path}\33[0m")

# Example usage
if __name__ == "__main__":
    
    directory = Path(os.path.expanduser("~")) # Change this to the directory you want to scan
    rule_path = str(Path('./rules.yar'))
    
    print(f'\33[32mScanning {directory} ...\33[30m ')
    scanner = YaraScanner(directory, rule_path)
    
    scanner.scan_directory()
