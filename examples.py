from blackburn import LockFile, Net, CrudSieve
import time

print(f"Outside IP is {Net.outside()}")
print(f"This host's IP is {Net.local()}")
print(f"Lag is currently {Net.latency('4.2.2.2')}ms")
print(f"Network stability at {Net.stability('google.com')}%")
bad_ip = "abc"
print(f"Is {bad_ip} a valid IP? {Net.is_valid_ip(bad_ip)}")

malicious_string = "'; while(1);var foo='bar"
malicious_thing = {
    "$ne": "\r\na",
    "$tuff/\/\/": [-99223372036854775809.2, malicious_string],
    "E\/xample$$": set(["a", "b", "c"]),
}
clean_string = CrudSieve.clean(malicious_string)
clean_thing = CrudSieve.clean(malicious_thing)

lock = LockFile("temp/test.lock")
with lock:
    print("I got lock!")
    time.sleep(5)
