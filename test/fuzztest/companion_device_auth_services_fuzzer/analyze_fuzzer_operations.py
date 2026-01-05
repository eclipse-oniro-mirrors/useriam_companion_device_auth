# Copyright (c) 2025 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#!/usr/bin/env python3
"""
Analyze FUZZ test operations and generate optimization plan.
"""

import os
import re
from pathlib import Path
from collections import defaultdict

# Base directories
FUZZER_DIR = Path("./cases")
SERVICES_DIR = Path("../../../../../code/companion_device_auth/services")

def count_operations_in_fuzzer(fuzzer_path):
    """Count NUM_FUZZ_OPERATIONS in a fuzzer file."""
    try:
        with open(fuzzer_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Find NUM_FUZZ_OPERATIONS definition
        match = re.search(r'constexpr uint8_t NUM_FUZZ_OPERATIONS\s*=\s*([^;]+);', content)
        if match:
            expr = match.group(1).strip()
            # Handle sizeof calculation
            if 'sizeof' in expr:
                # Try to extract array size from g_fuzzFuncs
                array_match = re.search(r'static const FuzzFunction g_fuzzFuncs\[\]\s*=\s*\{([^}]+)\}', content, re.DOTALL)
                if array_match:
                    funcs = array_match.group(1)
                    # Count function references
                    count = len([line for line in funcs.split('\n') if line.strip() and not line.strip().startswith('//')])
                    return count
            return int(expr) if expr.isdigit() else 0

        # Alternative: count FuzzFunction array entries
        array_match = re.search(r'static const FuzzFunction g_fuzzFuncs\[\]\s*=\s*\{([^}]+)\}', content, re.DOTALL)
        if array_match:
            funcs = array_match.group(1)
            count = len([line for line in funcs.split('\n') if line.strip() and not line.strip().startswith('//')])
            return count

        return 0
    except Exception as e:
        print(f"Error analyzing {fuzzer_path}: {e}")
        return 0

def get_fuzzer_files():
    """Get all fuzzer files."""
    fuzzer_files = []
    for cpp_file in FUZZER_DIR.rglob("*_fuzzer.cpp"):
        fuzzer_files.append(cpp_file)
    return sorted(fuzzer_files)

def map_fuzzer_to_service(fuzzer_path):
    """Map fuzzer file to corresponding service file."""
    fuzzer_name = fuzzer_path.stem  # e.g., "companion_fuzzer"

    # Remove _fuzzer suffix
    class_name = fuzzer_name.replace('_fuzzer', '')

    # Find matching service file
    for service_file in SERVICES_DIR.rglob(f"{class_name}.cpp"):
        return service_file

    return None

def parse_coverage_report():
    """Parse the coverage report to get uncovered methods."""
    report_path = Path("./out/cmake/coverage/method_coverage_report.md")
    if not report_path.exists():
        return {}

    uncovered = defaultdict(list)

    with open(report_path, 'r', encoding='utf-8') as f:
        current_file = None

        for line in f:
            if line.startswith("## services/"):
                current_file = line.strip().replace("## ", "")
            elif line.startswith("- [ ]") and current_file:
                method = line.strip().replace("- [ ] ", "")
                uncovered[current_file].append(method)

    return uncovered

def main():
    """Main analysis function."""
    print("=" * 80)
    print("FUZZ Test Operations Analysis")
    print("=" * 80)

    # Get all fuzzer files
    fuzzer_files = get_fuzzer_files()
    print(f"\nTotal fuzzer files: {len(fuzzer_files)}")

    # Count operations per fuzzer
    total_operations = 0
    fuzzer_stats = []

    for fuzzer_path in fuzzer_files:
        ops = count_operations_in_fuzzer(fuzzer_path)
        total_operations += ops
        fuzzer_stats.append((fuzzer_path.name, ops, fuzzer_path.parent.name))

    # Sort by operation count
    fuzzer_stats.sort(key=lambda x: x[1])

    print(f"\nTotal operations across all fuzzers: {total_operations}")
    print(f"\nFuzzers with NO operations (need fixing):")
    no_ops = [f for f in fuzzer_stats if f[1] == 0]
    for name, _, category in no_ops:
        print(f"  - [{category}] {name}: 0 operations")

    print(f"\nFuzzers with FEW operations (priority for expansion):")
    few_ops = [f for f in fuzzer_stats if 0 < f[1] < 5]
    for name, ops, category in few_ops:
        print(f"  - [{category}] {name}: {ops} operations")

    print(f"\nTop 20 fuzzers by operation count:")
    top_ops = sorted(fuzzer_stats, key=lambda x: x[1], reverse=True)[:20]
    for name, ops, category in top_ops:
        print(f"  - [{category}] {name}: {ops} operations")

    # Parse coverage report
    uncovered = parse_coverage_report()
    print(f"\nFiles with uncovered methods:")
    sorted_files = sorted(uncovered.items(), key=lambda x: len(x[1]), reverse=True)[:20]
    for file, methods in sorted_files:
        print(f"  {file}: {len(methods)} uncovered methods")

    # Calculate gap to target
    target_operations = 350
    gap = target_operations - total_operations

    print("\n" + "=" * 80)
    print("OPTIMIZATION PLAN")
    print("=" * 80)
    print(f"Current operations: {total_operations}")
    print(f"Target operations: {target_operations}")
    print(f"Gap: {gap} additional operations needed")
    print()

    # Suggest improvements
    if no_ops:
        print(f"1. FIX EMPTY FUZZERS ({len(no_ops)} files):")
        print(f"   Priority: CRITICAL - These fuzzers contribute nothing")
        for name, _, category in no_ops[:10]:
            print(f"   - [{category}] {name}")
        if len(no_ops) > 10:
            print(f"   ... and {len(no_ops) - 10} more")
        print()

    if few_ops:
        print(f"2. EXPAND LOW-COUNT FUZZERS ({len(few_ops)} files):")
        print(f"   Priority: HIGH - Add 3-5 more operations each")
        for name, ops, category in few_ops[:10]:
            print(f"   - [{category}] {name}: {ops} → target {ops + 5}")
        if len(few_ops) > 10:
            print(f"   ... and {len(few_ops) - 10} more")
        print()

    if uncovered:
        print(f"3. IMPROVE COVERAGE ({len(uncovered)} files with uncovered methods):")
        total_uncovered = sum(len(methods) for methods in uncovered.values())
        print(f"   Priority: MEDIUM - {total_uncovered} uncovered methods total")
        print(f"   Top 10 files:")
        for file, methods in sorted_files[:10]:
            fuzzer_name = Path(file).stem + "_fuzzer.cpp"
            print(f"   - {fuzzer_name}: {len(methods)} uncovered")
        print()

    # Calculate realistic potential
    potential_from_empty = len(no_ops) * 8  # Assume 8 ops per fixed fuzzer
    potential_from_few = len(few_ops) * 5   # Assume +5 ops per expansion
    potential_from_coverage = min(sum(len(m) for m in uncovered.values()), 100)

    total_potential = potential_from_empty + potential_from_few + potential_from_coverage
    projected = total_operations + total_potential

    print("PROJECTION:")
    print(f"  Potential from empty fuzzers: +{potential_from_empty} operations")
    print(f"  Potential from few-operation fuzzers: +{potential_from_few} operations")
    print(f"  Potential from coverage improvements: +{potential_from_coverage} operations")
    print(f"  Total potential: +{total_potential} operations")
    print(f"  Projected total: {projected} operations")
    print()

    if projected >= target_operations:
        print(f"✓ Target ACHIEVABLE: Can reach {target_operations} operations")
    else:
        print(f"✗ Target may need adjustment or more aggressive optimization")

if __name__ == "__main__":
    os.chdir(Path(__file__).parent)
    main()
