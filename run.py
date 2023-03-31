from sitesniffer import *
from typing import Dict

# Function to display a dictionary more clearly
def print_dictionary(d: Dict[str, str]) -> None:
    for key, value in d.items():
        print(f"\033[32m{key}\033[0m: \033[37m{value}\033[0m")

print_dictionary(get_site_info("https://youtube.com"))