import os
import time
import threading
import shutil
from pathlib import Path

class FileMonitorTester:
    def __init__(self, test_dir="test_files"):
        self.test_dir = test_dir
        self.setup_test_environment()

    def setup_test_environment(self):
        """Create test directory and initial files"""
        # Clean up any existing test directory
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
        
        # Create fresh test directory
        os.makedirs(self.test_dir)
        
        # Create initial test files
        self.create_test_files()
        
    def create_test_files(self):
        """Create initial set of test files"""
        files = {
            'file1.txt': 'Initial content for file 1',
            'file2.txt': 'Initial content for file 2',
            'file3.txt': 'Initial content for file 3'
        }
        
        for filename, content in files.items():
            with open(os.path.join(self.test_dir, filename), 'w') as f:
                f.write(content)

    def run_modification_tests(self):
        """Run a series of file modifications"""
        print("\nStarting modification tests...")
        time.sleep(2)  # Give time for monitoring to start
        
        # Test 1: Modify existing file
        print("Test 1: Modifying existing file...")
        with open(os.path.join(self.test_dir, 'file1.txt'), 'a') as f:
            f.write('\nModified content')
        time.sleep(2)
        
        # Test 2: Create new file
        print("Test 2: Creating new file...")
        with open(os.path.join(self.test_dir, 'new_file.txt'), 'w') as f:
            f.write('New file content')
        time.sleep(2)
        
        # Test 3: Delete file
        print("Test 3: Deleting file...")
        os.remove(os.path.join(self.test_dir, 'file2.txt'))
        time.sleep(2)
        
        # Test 4: Rapid modifications
        print("Test 4: Performing rapid modifications...")
        for i in range(5):
            with open(os.path.join(self.test_dir, f'rapid_file_{i}.txt'), 'w') as f:
                f.write(f'Rapid test content {i}')
            time.sleep(0.5)

        print("All tests completed!")

def main():
    # Create and run tests
    tester = FileMonitorTester()
    
    print("Test environment setup complete.")
    print(f"Please start the File Integrity Monitor and monitor the '{tester.test_dir}' directory.")
    input("Press Enter when ready to start tests...")
    
    # Run modification tests
    tester.run_modification_tests()

if __name__ == "__main__":
    main()