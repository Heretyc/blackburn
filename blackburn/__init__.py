import pathlib
from typing import Union
import bcrypt
import hashlib
import base64
import datetime
from netaddr import AddrFormatError, IPAddress
import socket
import requests
import sys
from math import log


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
        """
        Interprocess thread locking based on lock files.
        Useful for shared resource contention issues.
        :param lock_file: The path to a .lock file. If the file exists, the resource is considered 'in use'
        """
        assert isinstance(
            lock_file, (str, pathlib.Path)
        ), "lock_file must be a pathlib.Path() or a string path"
        self.lock_file = pathlib.Path(lock_file).resolve()
        assert (
            self.lock_file.suffix == ".lock"
        ), "lock_file must end in a '.lock' extension"
        self.lock_file.parent.mkdir(parents=True, exist_ok=True)

    def override_lock(self):
        """
        Forcibly 'unlocks' the lock file regardless of status
        """
        try:
            self.lock_file.unlink()
        except FileNotFoundError:
            pass

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
    :return: Returns a dictionary of the JSON file contents
    :rtype: dict
    """
    import json

    assert isinstance(
        json_file, (str, pathlib.Path)
    ), "json_file must be a pathlib.Path() or a string path"
    file_path = pathlib.Path(json_file)
    try:
        with file_path.open("r") as file_data:
            return json.load(file_data)
    except FileNotFoundError:
        raise FileNotFoundError(f"Error: {file_path} not found.")
    except json.decoder.JSONDecodeError:
        raise ValueError(f"Error: {file_path} is not a properly formatted JSON file")


def save_json_file(
    json_file: Union[str, pathlib.Path], dictionary_to_save: dict, retries: int = 3
) -> None:
    """
    Writes a new JSON file to disk. If the file exists, it will be overwritten.
    :param json_file: JSON file to write into
    :param dictionary_to_save:
    :param retries: If file is locked for any reason, retry writing this number of times
    :return: None
    """
    import json
    import random
    import time

    assert isinstance(retries, int), "Retries parameter must be an integer"
    assert retries >= 0, "Retries must be a positive integer"
    assert isinstance(
        json_file, (str, pathlib.Path)
    ), "json_file must be a pathlib.Path() or a string path"
    file_path = pathlib.Path(json_file)
    while retries >= 0:
        retries -= 1
        try:
            with file_path.open("w") as file:
                return json.dump(dictionary_to_save, file, ensure_ascii=False)
        except PermissionError:
            wait_time = random.random()
            time.sleep(wait_time)
    raise PermissionError(f"Permission issue while writing JSON: {file_path}")


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
        self._kwargs = kwargs
        if isinstance(config_json, (str, pathlib.Path)):
            config_path = pathlib.Path(config_json)
        self.config = load_json_file(config_path)
        try:
            assert len(self.config["libblackburn"]["salt"])
        except (KeyError, AssertionError):
            new_salt = self.new_salt()
            self.config["libblackburn"]["salt"] = bytes.decode(new_salt)
            save_json_file(config_path, self.config)

        self._db = self._connect_db()
        self._db_config_name = "__config__"
        self._db_config = self._get_db_config()

    def _connect_db(self):
        import mongoblack

        return mongoblack.Connection(
            self.config["libblackburn"]["instance"],
            self.config["libblackburn"]["user"],
            self.config["libblackburn"]["pass"],
            self.config["libblackburn"]["uri"],
            **self._kwargs,
        )

    def _get_db_config(self) -> dict:
        db_config = self._db.get(
            self.config["libblackburn"]["user_database"], self._db_config_name
        )
        if db_config is None:
            config_doc = {"salt": self.new_salt(), "key_derivation_ops": 100}
            self._db.write(
                self.config["libblackburn"]["user_database"],
                config_doc,
                self._db_config_name,
            )
            db_config = self._db.get(
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

    def update_attribute(self, username: str, attribute_value_tuple: tuple):
        """
        Updates the specified user attribute in the database
        :param username: Account name credential
        :param attribute_value_tuple: (key, value) to update
        :return:
        """
        username = self._user_pipeline(username)
        user_document = self._db.get(
            self.config["libblackburn"]["user_database"], username
        )
        key = attribute_value_tuple[0]
        value = attribute_value_tuple[1]
        user_document["attributes"][key] = value
        return self._db.write(
            self.config["libblackburn"]["user_database"], user_document, username
        )

    def get_attributes(self, username: str) -> dict:
        """
        Retrieves all available attributes for the specified user as a dict
        :param username: Account name credential
        :return: The complete dictionary of all user attributes
        """
        username = self._user_pipeline(username)
        user_document = self._db.get(
            self.config["libblackburn"]["user_database"], username
        )
        return user_document["attributes"]

    def add_user(self, username: str, plaintext_password: str, attributes: dict = None):
        """
        Adds the specified user to the database. Optionally with the specified dict object as additional attributes
        :param username: Account name credential
        :param plaintext_password: Account password credential
        :param attributes:
        :return:
        """
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
        return self._db.write(
            self.config["libblackburn"]["user_database"], document, username
        )

    def update_password(self, username: str, plaintext_password: str):
        """
        Updates the specified user credential in the database
        :param username: Account name credential
        :param plaintext_password: Account password credential
        """
        username = self._user_pipeline(username)
        user_document = self._db.get(
            self.config["libblackburn"]["user_database"], username
        )
        password = self._password_pipeline(plaintext_password)
        user_document["password"] = password
        self._db.write(
            self.config["libblackburn"]["user_database"], user_document, username
        )

    def delete_user(self, username: str):
        """
        Delete the specified user from the database, action is permanent
        :param username: Account name credential
        :return:
        """
        username = self._user_pipeline(username)
        return self._db.delete(self.config["libblackburn"]["user_database"], username)

    def verify(self, username: str, password: str) -> bool:
        """
        Verify the supplied username/password are correct versus the database record
        :param username: Account name credential
        :param password: Account password credential
        :return: True/False if password is correct
        """
        username = self._user_pipeline(username)
        user_doc = self._db.get(self.config["libblackburn"]["user_database"], username)
        assert username == user_doc["_id"]
        pw_hash = user_doc["password"]
        encoded_pass = self._password_pipeline(password)
        return pw_hash == encoded_pass


def DEBUG_DISABLE_UNSAFE_TLS_WARNING():
    """
    Prevents modules which use urllib3 like 'requests', from generating self-signed and invalid cert warnings
    Should ONLY be used in non-production builds for testing and development
    """
    import urllib3

    urllib3.disable_warnings()


def time_stamp_read(time_string: str) -> datetime:
    """
    Reads a properly formatted ISO 8601 time stamp into memory as a datetime object
    :param time_string:
    :return: a datetime.datetime object reflective of the ISO 8601 data
    """
    return datetime.datetime.fromisoformat(time_string.strip())


def time_stamp_convert(datetime_object: datetime.datetime) -> str:
    """
    Converts a datetime object into an ISO 8601 time stamp with current timezone data
    :param datetime_object: datetime object you wish to convert
    :return: ISO 8601 time stamp string
    """
    timezone = datetime.datetime.now(datetime.timezone.utc).astimezone().tzinfo
    return datetime_object.replace(tzinfo=timezone).isoformat()


def time_stamp_now() -> str:
    """
    Creates an ISO 8601 time stamp from the current time with timezone data
    :return: ISO 8601 time stamp string
    """
    return time_stamp_convert(datetime.datetime.now())


def time_now() -> datetime:
    """
    Creates a timezone-aware datetime object with current timezone
    :return: a datetime.datetime object reflective of the current timezone
    """
    timezone = datetime.datetime.now(datetime.timezone.utc).astimezone().tzinfo
    return datetime.datetime.now().replace(tzinfo=timezone)


class ETA:
    def __init__(self, total_items, **kwargs):
        """
        ETA calculates estimated time to completion by tracking how many items are processed with each call of report()
        :param total_items: Total number of items which are to be processed
        :keyword file: (default: None) If specified, attempts to save ETA state to disk and potentially pass state to parallel threads/ processes
        :keyword interval: Time in seconds between reporting ETA from successive calls of report()
        :keyword precise_eta: (default: False) If True, reports the ETA as well as the exact time of day when completion is expected
        """
        assert isinstance(
            total_items, (int, float)
        ), "_total_items must be an integer or float"
        self.file = kwargs.get("file", None)
        self.interval = kwargs.get("interval", 5)
        assert isinstance(
            self.interval, int
        ), "interval must be an integer representing the number of seconds between updates"
        self.precise_eta = kwargs.get("precise_eta", False)
        assert isinstance(self.precise_eta, bool), "precise_eta must be True or False"
        self._master_db = {}
        self._total_items = total_items
        self._total_items_processed = 0
        self._max_log_size = 20

    def _to_string(self, log_tuple: tuple) -> str:
        return f"{log_tuple[0]} {time_stamp_convert(log_tuple[1])}"

    def _to_binary(self, log_string: str) -> tuple:
        items = log_string.split()
        return items[0], time_stamp_read(items[1])

    def _load_master_db(self):
        if not isinstance(self.file, (pathlib.Path, str)):
            return

        incoming_db = load_json_file(self.file)

        try:
            self._master_db = {
                "log": [],
                "last_update": time_stamp_read(incoming_db["last_update"]),
                "_total_items": incoming_db["_total_items"],
                "_total_items_processed": incoming_db["_total_items_processed"],
            }
        except KeyError:
            return

        for log_entry in incoming_db["log"]:
            items, dt = self._to_binary(log_entry)
            items = float(items)
            self._master_db["log"].append((items, dt))

    def _save_master_db(self):
        if not isinstance(self.file, (pathlib.Path, str)):
            return
        outbound_db = {
            "log": [],
            "last_update": time_stamp_convert(self._master_db["last_update"]),
            "_total_items": self._master_db["_total_items"],
            "_total_items_processed": self._master_db["_total_items_processed"],
        }
        for log_entry in self._master_db["log"]:
            serialized = self._to_string(log_entry)
            outbound_db["log"].append(serialized)

        save_json_file(self.file, outbound_db)

    def _log_intervals_calc_per_sec(self, item_a: tuple, item_b: tuple) -> int:
        a_items = item_a[0]
        a_dt = item_a[1]

        b_items = item_b[0]
        b_dt = item_b[1]

        delta_items = abs(a_items - b_items)
        delta_seconds = abs(a_dt.second - b_dt.second)
        if delta_seconds < 1:
            delta_seconds = 0.5
        return delta_items / delta_seconds

    def _order_logs(self):
        new_list = []
        for log_tuple in self._master_db["log"]:
            assert isinstance(
                log_tuple, tuple
            ), "_master_db logs contain non-binary data"
            assert isinstance(
                log_tuple[0], (int, float)
            ), "Log entry contained malformed items_processed data"
            assert isinstance(
                log_tuple[1], datetime.datetime
            ), "Log entry contained malformed datetime data"
            for log_tuple_in_review in new_list:
                if (log_tuple[1] > log_tuple_in_review[1]) and not (
                    log_tuple[1] == log_tuple_in_review[1]
                ):
                    new_list.append(log_tuple)
                    break
            if len(new_list) < 1:
                new_list.append(log_tuple)
        self._master_db["log"] = new_list

        while len(self._master_db["log"]) > self._max_log_size:
            self._master_db["log"].pop(0)

    def _send_update(self) -> str:
        self._master_db["last_update"] = time_now()
        from statistics import mean
        import humanize

        self._order_logs()
        list_of_averages_per_sec = []
        for index in range(len(self._master_db["log"])):
            try:
                per_sec = self._log_intervals_calc_per_sec(
                    self._master_db["log"][index], self._master_db["log"][index + 1]
                )
            except IndexError:
                break
            list_of_averages_per_sec.append(per_sec)
        average_per_sec = mean(list_of_averages_per_sec)
        remaining = (
            self._master_db["_total_items"] - self._master_db["_total_items_processed"]
        )
        seconds_left = remaining * average_per_sec

        if seconds_left < 0:
            seconds_left = 0

        future_completion_dt = humanize.naturaldelta(
            datetime.timedelta(seconds=seconds_left)
        )
        if self.precise_eta:
            future_time = (
                datetime.datetime.now() + datetime.timedelta(seconds=seconds_left)
            ).strftime("%I:%M%p")
            return f"{future_completion_dt} @ {future_time}"
        else:
            return f"{future_completion_dt}"

    def purge_logs(self):
        """
        Deletes the retained state found in the user specified storage file. Has no effect if ETA(_,file=file_path) has not been specified.
        :return: No returns
        """
        if not isinstance(self.file, (pathlib.Path, str)):
            return
        self._master_db = {}
        save_json_file(self.file, self._master_db)

    def report(self, items_processed: Union[int, float]) -> Union[str, None]:
        """
        Report completion of items. If the proper number of seconds has elapsed, returns an ETA string.
        :param items_processed: The number of items that have processed since the last time ETA.report() was called
        :return: Returns a string with the estimated completion time. If it is not time to report an ETA, returns None type
        """
        current_time = time_now()
        assert isinstance(
            items_processed, (int, float)
        ), "items_processed must be an integer or float"
        try:
            self._load_master_db()
        except FileNotFoundError:
            pass
        try:
            if (
                abs(current_time.second - self._master_db["last_update"].second)
                >= self.interval
            ):
                send_update = True
            else:
                send_update = False
            self._master_db["_total_items_processed"] += items_processed
        except KeyError:
            self._master_db = {
                "log": [(items_processed, current_time)],
                "last_update": current_time,
                "_total_items": self._total_items,
                "_total_items_processed": items_processed,
            }
            return "ETA not yet available"
        self._master_db["log"].append((items_processed, current_time))
        if send_update:
            result = self._send_update()
        else:
            result = None

        self._save_master_db()
        return result

    def __repr__(self):
        try:
            self._load_master_db()
        except FileNotFoundError:
            pass
        return self._send_update()


class Net:
    icmp_seed_ids = set([])

    @staticmethod
    def is_valid_ip(possible_ip):
        """
        Simply checks if the given text contains a proper IPv4 or IPv6 address.
        :param possible_ip: The string which supposedly has an IP address
        :return: (bool) True if this is an IP, False if not an IP
        """
        try:
            IPAddress(possible_ip)
            return True
        except AddrFormatError:
            return False

    @classmethod
    def local(cls) -> str:
        """
        Determines the default local route for this machine
        :return: (str) IP Address of this machine
        """

        socket_object = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        socket_object.connect(("8.8.8.8", 80))
        ip_address = socket_object.getsockname()[0]
        if cls.is_valid_ip(ip_address):
            return ip_address
        else:
            return "unavailable"

    @classmethod
    def outside(cls, quiet: bool = False) -> str:
        """
        Determines the outside public IP address of this machine
        :param quiet: (bool) Whether errors should be silenced on terminal
        :return: (str) Outside IP address of this machine
        """

        remaining = 10
        response = None
        while remaining > 0:
            remaining -= 1
            try:
                response = requests.get("https://icanhazip.com")
                break
            except (
                requests.exceptions.ConnectTimeout,
                requests.exceptions.ReadTimeout,
                requests.exceptions.ConnectionError,
            ):
                pass
        if response is None:
            if not quiet:
                print("Unable to reach outside internet domains")
            return "unavailable"
        try:
            ipaddress = response.text.strip()
        except AttributeError:
            return "unavailable"
        if cls.is_valid_ip(ipaddress):
            return ipaddress
        else:
            return "unavailable"

    @classmethod
    def latency(cls, host: str) -> float:
        """
        Determines network latency in Milliseconds to the designated host
        :param host:  Hostname or IP address to test
        :return: Returns the latency in ms
        """
        from pythonping import executor, payload_provider
        from random import randint

        provider = payload_provider.Repeat(b"", 1)

        # Allow for multithreaded usage;
        while True:
            seed_id = randint(0x1, 0xFFFF)
            if seed_id not in cls.icmp_seed_ids:
                cls.icmp_seed_ids.add(seed_id)
                break

        comm = executor.Communicator(host, provider, 900, 0, seed_id=seed_id)
        comm.run(match_payloads=True)

        cls.icmp_seed_ids.remove(seed_id)

        response = comm.responses
        return response.rtt_avg_ms

    @classmethod
    def stability(cls, host: str) -> int:
        """
        Determines percent packet success to the designated host.
        :param host: Hostname or IP address to test
        :return: Returns a percentage representing how stable the link is (100 is best)
        """
        from pythonping import executor, payload_provider
        from random import randint

        provider = payload_provider.Repeat(b"", 5)

        # Allow for multithreaded usage;
        while True:
            seed_id = randint(0x1, 0xFFFF)
            if seed_id not in cls.icmp_seed_ids:
                cls.icmp_seed_ids.add(seed_id)
                break

        comm = executor.Communicator(host, provider, 900, 0.2, seed_id=seed_id)
        comm.run(match_payloads=True)

        cls.icmp_seed_ids.remove(seed_id)

        response = comm.responses
        return round(100 - response.packet_loss)


class CrudSieve:

    _nonprintable = {
        i: None for i in range(0, sys.maxunicode + 1) if not chr(i).isprintable()
    }
    _ignored = {36: None, 59: None}

    _escaped = str.maketrans(
        {
            "-": r"\-",
            "]": r"\]",
            "\\": r"\\",
            "^": r"\^",
            "$": r"\$",
            "*": r"\*",
            ".": r"\.",
        }
    )

    @classmethod
    def _remove_nonprintable(cls, string_to_filter: str) -> str:
        return string_to_filter.translate(cls._nonprintable)

    @classmethod
    def _escape_all(cls, string_to_filter: str) -> str:
        return string_to_filter.translate(cls._escaped)

    @classmethod
    def _paranoid(cls, string_to_filter):
        return string_to_filter.translate(cls._ignored)

    @classmethod
    def _calc_num_bytes(cls, number_to_calculate):
        return int(log(abs(number_to_calculate), 256)) + 1

    @classmethod
    def _check_numbers(cls, number_to_check):
        if cls._calc_num_bytes(number_to_check) >= 8:
            return "{:.15e}".format(number_to_check)
        else:
            return number_to_check

    @classmethod
    def _check_string_size(cls, string_to_check):
        if len(string_to_check) >= 2147483647:
            return string_to_check[:2147483636] + "[truncated]"
        else:
            return string_to_check

    @classmethod
    def clean(
        cls,
        object_to_filter: Union[str, int, float, dict, set, list, bool],
        relaxed: bool = False,
    ) -> Union[str, int, float, dict, set, list, bool]:
        """
        Begins object sanitization, set relaxed=True to keep problematic characters like $ and ; in the object
        :param object_to_filter: Accepts str, int, float, dict, set, list, bool
        :param relaxed: (bool) Set to True to keep problematic characters like $ and ; in the object.
        :return: Returns a sanitized version of the object passed
        """
        if isinstance(object_to_filter, str):
            if not relaxed:
                object_to_filter = cls._paranoid(object_to_filter)
            object_to_filter = cls._remove_nonprintable(object_to_filter)
            object_to_filter = cls._escape_all(object_to_filter)
            object_to_filter = cls._check_string_size(object_to_filter)
            return object_to_filter
        elif isinstance(object_to_filter, list):
            new_list = []
            for item in object_to_filter:
                new_list.append(cls.clean(item, relaxed))
            return new_list
        elif isinstance(object_to_filter, set):
            new_set = set()
            for item in object_to_filter:
                new_set.add(cls.clean(item, relaxed))
            return new_set
        elif isinstance(object_to_filter, dict):
            new_dict = {}
            for key, value in object_to_filter.items():
                clean_key = cls.clean(key, relaxed)
                clean_value = cls.clean(value, relaxed)
                new_dict[clean_key] = clean_value
            return new_dict
        elif isinstance(object_to_filter, int):
            object_to_filter = cls._check_numbers(object_to_filter)
            return object_to_filter
        elif isinstance(object_to_filter, float):
            object_to_filter = cls._check_numbers(object_to_filter)
            return object_to_filter
        elif isinstance(object_to_filter, bool):
            return object_to_filter
        else:
            if relaxed:
                return object_to_filter
            else:
                return ""
