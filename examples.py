from blackburn import LockFile
import time

lock = LockFile("temp/test.lock")
with lock:
    print("I got lock!")
    time.sleep(10)
