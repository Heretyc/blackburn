import pathlib
from typing import Union
import bcrypt
import hashlib
import base64

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
    def __init__(self, lock_file: Union[str, pathlib.Path]):
        assert isinstance(
            lock_file, (str, pathlib.Path)
        ), "lock_file must be a pathlib.Path() or a string path"
        self.lock_file = pathlib.Path(lock_file).resolve()
        assert (
            self.lock_file.suffix == ".lock"
        ), "lock_file must end in a '.lock' extension"
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


def load_json_file(json_file: Union[str, pathlib.Path]) -> dict:
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
        raise FileNotFoundError(f"Error: {file_path} not found.")
    except json.decoder.JSONDecodeError:
        raise ValueError(f"Error: {file_path} is not a properly formatted JSON file")


class UserDB:
    def __init__(self, config_json: Union[str, pathlib.Path], **kwargs):
        """
        Initializes the database connection using the supplied configuration file.
        :param config_json: Pathlib path, or string containing the path to the configuration JSON file
        :keyword compression: MongoDB Zlib compression level (default: 1)
        :keyword tls: MongoDB SSL/TLS state (default: True)
        :keyword retries: MongoDB Number of attempted retries for operations
        :keyword timeout: MongoDB Cool-down period in seconds between successive retries (default: 0.5)
        """
        self.kwargs = kwargs
        if isinstance(config_json, (str, pathlib.Path)):
            config_path = pathlib.Path(config_json)
        self.config = load_json_file(config_path)
        self.db = self._connect_db()
        self._db_config_name = "__config__"
        self._db_config = self._get_db_config()

    def _connect_db(self):
        import mongoblack

        return mongoblack.Connection(
            self.config["libblackburn"]["instance"],
            self.config["libblackburn"]["user"],
            self.config["libblackburn"]["pass"],
            self.config["libblackburn"]["uri"],
            **self.kwargs,
        )

    def _get_db_config(self) -> dict:
        db_config = self.db.get(
            self.config["libblackburn"]["user_database"], self._db_config_name
        )
        if db_config is None:
            config_doc = {"salt": self.new_salt(), "key_derivation_ops": 100}
            self.db.write(
                self.config["libblackburn"]["user_database"],
                config_doc,
                self._db_config_name,
            )
            db_config = self.db.get(
                self.config["libblackburn"]["user_database"], self._db_config_name
            )
        return db_config

    def _salt_password(self, password: str):
        return f"salted-{self.config['salt']}{password}{self._db_config['salt']}"

    def _key_derivation(self, hashed_password):
        return bcrypt.kdf(
            password=hashed_password,
            salt=self._db_config["salt"],
            desired_key_bytes=64,
            rounds=100,
        )

    def _hash(self, string_to_hash: str):
        bytes_to_hash = str.encode(string_to_hash)
        return base64.b64encode(hashlib.sha256(bytes_to_hash).digest())

    @staticmethod
    def new_salt() -> bytes:
        """
        Generates a cryptographic-quality seed value. (Also known as "salt")
        :return: Returns a high entropy seed value (salt)
        """
        return bcrypt.gensalt()

    def _user_pipeline(self, username: str) -> str:
        return username.lower().strip()

    def _password_pipeline(self, password: str) -> bytes:
        salted = self._salt_password(password)
        hashed = self._hash(salted)
        complete = self._key_derivation(hashed)
        return complete

    def update_user_attribute(self, username: str, attribute_value_tuple: tuple):
        username = self._user_pipeline(username)
        user_document = self.db.get(
            self.config["libblackburn"]["user_database"], username
        )
        key = attribute_value_tuple[0]
        value = attribute_value_tuple[1]
        user_document["attributes"][key] = value
        return self.db.write(
            self.config["libblackburn"]["user_database"], user_document, username
        )

    def write_user(
        self, username: str, plaintext_password: str, attributes: dict = None
    ):
        username = self._user_pipeline(username)
        password = self._password_pipeline(plaintext_password)
        document = {"password": password}
        if attributes is not None:
            assert isinstance(
                attributes, dict
            ), "attributes argument must be a dictionary"
        else:
            attributes = {}
        document["attributes"] = attributes
        return self.db.write(
            self.config["libblackburn"]["user_database"], document, username
        )

    def update_user_password(self, username: str, plaintext_password: str):
        username = self._user_pipeline(username)
        user_document = self.db.get(
            self.config["libblackburn"]["user_database"], username
        )
        password = self._password_pipeline(plaintext_password)
        user_document["password"] = password
        self.db.write(
            self.config["libblackburn"]["user_database"], user_document, username
        )
        user_document

    def delete_user(self, username: str):
        username = self._user_pipeline(username)
        return self.db.delete(self.config["libblackburn"]["user_database"], username)

    def password_is_accurate(self, username: str, password: str) -> bool:
        username = self._user_pipeline(username)
        user_doc = self.db.get(self.config["libblackburn"]["user_database"], username)
        assert username == user_doc["_id"]
        pw_hash = user_doc["password"]
        encoded_pass = self._password_pipeline(password)
        return pw_hash == encoded_pass
