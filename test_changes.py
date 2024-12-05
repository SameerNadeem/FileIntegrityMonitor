# Create this script as test_changes.py
import time
import os

def make_changes():
    # Create a new file
    with open('test_files/test_multiple1.txt', 'w') as f:
        f.write('Initial content')
    time.sleep(2)
    
    # Modify the file
    with open('test_files/test_multiple1.txt', 'a') as f:
        f.write('\nModified content')
    time.sleep(2)
    
    # Create another file
    with open('test_files/test_multiple2.txt', 'w') as f:
        f.write('Second file')
    time.sleep(2)
    
    # Delete first file
    os.remove('test_files/test_multiple1.txt')

if __name__ == "__main__":
    make_changes()