import os

def test_github_requirements():
    print("=" * 60)
    print("GITHUB REPOSITORY REQUIREMENTS TEST")
    print("=" * 60)
    
    # 1. Check required files and directories
    required_files = ["README.md", "requirements.txt", ".env.example", "main.py"]
    required_dirs = ["src"]
    
    print("\n--- Checking Files & Directories ---")
    all_files_present = True
    for f in required_files:
        if os.path.exists(f):
            print(f"[PASS] Required file found: {f}")
        else:
            print(f"[FAIL] Missing required file: {f}")
            all_files_present = False
            
    for d in required_dirs:
        if os.path.isdir(d):
            print(f"[PASS] Required directory found: {d}/")
        else:
            print(f"[FAIL] Missing required directory: {d}/")
            all_files_present = False
            
    # 2. Check README.md contents
    print("\n--- Checking README.md Content ---")
    if os.path.exists("README.md"):
        with open("README.md", "r", encoding="utf-8") as f:
            readme_content = f.read().lower()
            
        required_sections = [
            ("description", "## description"),
            ("tech stack", "## tech stack"),
            ("setup instructions", "## setup instructions"),
            ("api endpoint", "## api endpoint"),
            ("approach", "## approach")
        ]
        
        all_sections_present = True
        for section_name, section_header in required_sections:
            if section_header in readme_content:
                print(f"[PASS] Required section found: {section_header}")
            else:
                print(f"[FAIL] Missing required section: {section_header}")
                all_sections_present = False
        
        # Check specific approach details
        approach_details = ["detect", "extract", "engage"]
        for detail in approach_details:
            if detail in readme_content:
                print(f"[PASS] Approach detail found mentioning: '{detail}'")
            else:
                print(f"[FAIL] Approach detail missing: '{detail}'")
                all_sections_present = False
    else:
        print("[FAIL] Cannot check README.md content because the file is missing.")
        all_sections_present = False
        
    print("\n" + "=" * 60)
    if all_files_present and all_sections_present:
        print("ALL GITHUB COMPLIANCE TESTS PASSED [PASS]")
        print("Your repository structure and README.md align perfectly with the hackathon's submission guidelines.")
    else:
        print("SOME TESTS FAILED [FAIL]")
        print("Please fix the missing requirements above before submitting.")
    print("=" * 60)

if __name__ == "__main__":
    test_github_requirements()
