import pathlib
"""Blackburn Library: Common library for projects created by Github @BlackburnHax"""

__author__ = "Brandon Blackburn"
__maintainer__ = "Brandon Blackburn"
__email__ = "contact@bhax.net"
__website__ = "https://keybase.io/blackburnhax"
__copyright__ = "Copyright 2021 Brandon Blackburn"
__license__ = "Apache 2.0"

#  Copyright (c) 2021. Brandon Blackburn - https://keybase.io/blackburnhax, Apache License, Version 2.0.
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#  http://www.apache.org/licenses/LICENSE-2.0
#  Unless required by applicable law or agreed to in writing,
#  software distributed under the License is distributed on an
#  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
#  either express or implied. See the License for the specific
#  language governing permissions and limitations under the License.
#  TL;DR:
#  For a human-readable & fast explanation of the Apache 2.0 license visit:  http://www.tldrlegal.com/l/apache2


class LockFile:
    def __init__(self, lock_file: [str, pathlib.Path]):
        assert isinstance(lock_file, (str, pathlib.Path)), "lock_file must be a pathlib.Path() or a string path"
        self.lock_file = pathlib.Path(lock_file).resolve()
        assert self.lock_file.suffix == ".lock", "lock_file must end in a '.lock' extension"
        self.lock_file.parent.mkdir(parents=True, exist_ok=True)

    def __enter__(self):
        import time
        import random
        while self.lock_file.exists():
            wait_time = random.random()
            time.sleep(wait_time)
        self.lock_file.touch()

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            self.lock_file.unlink()
        except FileNotFoundError:
            pass

def load_json_file(json_file: [str, pathlib.Path]) -> dict:
    """
    Loads a given JSON file into memory and returns a dictionary containing the result
    :param json_file: JSON file to load
    :type json_file: str
    :rtype: dict
    """
    import json
    file_path = pathlib.Path(json_file)
    try:
        with open(file_path, "r") as json_data:
            return json.load(json_data)
    except FileNotFoundError:
        print(f"Error: {file_path} not found.")
        raise FileNotFoundError