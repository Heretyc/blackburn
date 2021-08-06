from blackburn import LockFile, Net
import time

print(f"Outside IP is {Net.outside()}")
print(f"This host's IP is {Net.local()}")
print(f"Lag is currently {Net.latency('4.2.2.2')}ms")
print(f"Network stability at {Net.stability('google.com')}%")
bad_ip = "abc"
print(f"Is {bad_ip} a valid IP? {Net.is_valid_ip(bad_ip)}")

lock = LockFile("temp/test.lock")
with lock:
    print("I got lock!")
    time.sleep(5)
