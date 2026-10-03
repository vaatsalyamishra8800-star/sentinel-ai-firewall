"""
Sentinel - Lambda Packaging Utility
Builds a lean, zero-dependency zip deployment package (sentinel_lambda.zip)
containing lambda_function.py, detector.py, and policy.py.
Can be uploaded directly to AWS Lambda Console or deployed via SAM/CloudFormation.
"""

import os
import zipfile
import py_compile
import sys

FILES_TO_PACKAGE = [
    "lambda_function.py",
    "detector.py",
    "policy.py",
    "sentinel_sdk.py"
]

OUTPUT_ZIP = "sentinel_lambda.zip"


def build_package():
    print(f"[SENTINEL] Validating and packaging Lambda code into '{OUTPUT_ZIP}'...")

    # 1. Syntax check all files first
    for fname in FILES_TO_PACKAGE:
        if not os.path.exists(fname):
            print(f"[ERROR] Required file '{fname}' not found in current directory!", file=sys.stderr)
            sys.exit(1)
        try:
            py_compile.compile(fname, doraise=True)
            print(f"  + Syntax valid: {fname}")
        except py_compile.PyCompileError as e:
            print(f"[ERROR] Syntax error in {fname}: {e}", file=sys.stderr)
            sys.exit(1)

    # 2. Create Zip archive
    with zipfile.ZipFile(OUTPUT_ZIP, "w", zipfile.ZIP_DEFLATED) as zf:
        for fname in FILES_TO_PACKAGE:
            zf.write(fname, arcname=fname)
            print(f"  + Added to zip: {fname}")

    zip_size_kb = os.path.getsize(OUTPUT_ZIP) / 1024
    print(f"\n[SUCCESS] Package '{OUTPUT_ZIP}' created successfully! Size: {zip_size_kb:.1f} KB")
    print(f"Ready for AWS Lambda deployment.")


if __name__ == "__main__":
    build_package()
