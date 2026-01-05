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
# -*- coding: utf-8 -*-
"""
Generate method-level coverage report from LLVM coverage data.

This script parses LLVM coverage data and generates a markdown report
that matches the format of FUZZ_IMPORT_PLAN.md, showing which methods
are covered by the fuzz tests.

Usage:
    python3 generate_coverage_report.py [--fuzzer-bin PATH] [--profdata PATH] [--output FILE] [--services-dir PATH]

Environment:
    FUZZER_BIN: Path to the compiled fuzzer binary
    PROFDATA: Path to the merged profdata file
    OUTPUT: Output markdown file path
    SERVICES_DIR: Path to services source directory
"""

import os
import sys
import re
import subprocess
import argparse
from collections import defaultdict
from pathlib import Path


class CoverageAnalyzer:
    """Analyze LLVM coverage data and generate reports."""

    # Files excluded from FUZZ testing with reasons
    EXCLUDED_FILES = {
        # Virtual base classes with pure virtual methods - cannot be instantiated
        'services/cross_device_interaction/common/src/inbound_request.cpp':
            '虚基类，含纯虚方法 OnStart(), GetWeakPtr() - 无法实例化',
        'services/cross_device_interaction/common/src/outbound_request.cpp':
            '虚基类，含纯虚方法 OnConnected(), GetWeakPtr() - 无法实例化',

        # Infrastructure/utility classes - excluded by design requirements
        'services/singleton/src/singleton_manager.cpp':
            '单例管理器 - 基础设施类，按需求排除',
        'services/utils/src/resident_task_runner.cpp':
            '常驻任务运行器 - 基础设施类，按需求排除',
        'services/utils/src/task_runner_manager.cpp':
            '任务运行器管理器 - 基础设施类，按需求排除',
        'services/utils/src/temporary_task_runner.cpp':
            '临时任务运行器 - 基础设施类，按需求排除',
        'services/utils/src/relative_timer.cpp':
            '相对定时器 - 基础设施类，按需求排除',
        'services/utils/src/xcollie_helper.cpp':
            'XCollie 辅助工具 - 基础设施类，按需求排除',
    }

    def __init__(self, fuzzer_bin, profdata, services_dir, output_file):
        self.fuzzer_bin = fuzzer_bin
        self.profdata = profdata
        self.services_dir = Path(services_dir).resolve()
        self.output_file = output_file
        self.coverage_data = defaultdict(lambda: defaultdict(dict))
        self.file_methods = defaultdict(list)

    def run_llvm_cov(self):
        """Run llvm-cov report and parse output."""
        try:
            # First collect all source files from services directory
            source_files = []
            services_path = Path(self.services_dir)
            if services_path.exists():
                source_files = list(services_path.glob('**/*.cpp'))
                source_files = [str(f) for f in source_files
                               if '/test/' not in str(f) and '/fake/' not in str(f)]

            cmd = [
                'llvm-cov', 'report',
                self.fuzzer_bin,
                f'-instr-profile={self.profdata}',
                '-show-functions=true',
            ]

            # Add source files to command
            cmd.extend(str(f) for f in source_files)

            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            print(f"Error running llvm-cov: {e.stderr}", file=sys.stderr)
            sys.exit(1)
        except FileNotFoundError:
            print("Error: llvm-cov not found. Install LLVM tools.", file=sys.stderr)
            sys.exit(1)

    def parse_coverage_report(self, output):
        """Parse llvm-cov report output."""
        lines = output.split('\n')
        current_file = None

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # File header: "File 'path/to/file.cpp':"
            if line.startswith('File '):
                match = re.match(r"File '([^']+)':", line)
                if match:
                    current_file = match.group(1)
                    continue

            # Skip header and separator lines
            if line.startswith('Name') or line.startswith('---') or line.startswith('TOTAL'):
                continue

            # Function line: starts with mangled name (e.g., "_Z...")
            if current_file and line.startswith('_Z'):
                parts = line.split()
                if len(parts) >= 3:
                    mangled_name = parts[0]
                    regions = int(parts[1])
                    missed = int(parts[2])

                    # Demangle function name
                    try:
                        func_name = subprocess.check_output(
                            ['c++filt', mangled_name],
                            text=True
                        ).strip()

                        # Extract just the function name without parameters
                        func_name = re.sub(r'\(.*', '', func_name)
                        func_name = func_name.split('::')[-1]

                        # Skip template functions, operators, destructors
                        if any(skip in func_name for skip in ['<', 'operator', '~', '[']):
                            continue

                        # Check if covered (executed at least once)
                        covered = regions - missed > 0

                        if current_file not in [None, '']:
                            self.file_methods[current_file].append({
                                'name': func_name,
                                'covered': covered,
                                'regions': regions,
                                'missed': missed
                            })
                    except Exception:
                        continue

    def filter_services_files(self):
        """Filter to only include services files, excluding files in EXCLUDED_FILES."""
        filtered = {}
        excluded_info = []

        for file_path, methods in self.file_methods.items():
            # Check if this is a services file
            if 'companion_device_auth' not in file_path:
                continue

            # Exclude test, fake, out, unittest directories
            if any(skip in file_path for skip in ['/test/', '/fake/', '/out/', '/unittest/']):
                continue

            # Try to get relative path
            try:
                rel_path = str(Path(file_path).relative_to(self.services_dir.parent))
            except ValueError:
                # If not under services_dir, try to extract from the path
                match = re.search(r'(token-device-auth-design2/code/companion_device_auth/services/.+)', file_path)
                if match:
                    rel_path = match.group(1)
                else:
                    continue

            # Normalize the path for comparison (remove repo prefix if present)
            normalized_path = rel_path
            if 'token-device-auth-design2/code/companion_device_auth/' in normalized_path:
                normalized_path = normalized_path.split('token-device-auth-design2/code/companion_device_auth/')[1]

            # Check if this file is in the exclusion list
            if normalized_path in self.EXCLUDED_FILES:
                excluded_info.append((normalized_path, self.EXCLUDED_FILES[normalized_path]))
                continue

            filtered[rel_path] = methods

        # Log excluded files
        if excluded_info:
            print(f"\n[排除文件] 已排除 {len(excluded_info)} 个文件（按 FUZZ 策略）:")
            for file_path, reason in excluded_info:
                print(f"  - {file_path}: {reason}")

        return filtered

    def generate_report(self):
        """Generate markdown report."""
        # Run coverage analysis
        output = self.run_llvm_cov()
        self.parse_coverage_report(output)

        # Filter to services files
        filtered_files = self.filter_services_files()

        if not filtered_files:
            print("Warning: No services files found in coverage data", file=sys.stderr)

        # Sort by file path
        sorted_files = sorted(filtered_files.items())

        # Generate markdown
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write("# FUZZ 测试覆盖率报告\n\n")
            f.write("> 本报告由 `generate_coverage_report.py` 自动生成\n")
            f.write("> 覆盖率统计基于实际方法执行次数（执行次数 > 0 表示已覆盖）\n\n")

            # Add excluded files section
            if self.EXCLUDED_FILES:
                f.write("## 排除的文件（不进行 FUZZ 测试）\n\n")
                f.write("以下文件已按照 FUZZ 测试策略排除，不参与覆盖率统计：\n\n")
                for file_path, reason in sorted(self.EXCLUDED_FILES.items()):
                    f.write(f"### {file_path}\n")
                    f.write(f"- **排除原因**: {reason}\n\n")
                f.write("---\n\n")

            total_methods = 0
            covered_methods = 0

            for file_path, methods in sorted_files:
                # Extract file name
                file_name = Path(file_path).name
                file_dir = str(Path(file_path).parent).replace('token-device-auth-design2/code/companion_device_auth/', '')

                f.write(f"## {file_dir}/{file_name}\n\n")

                # Sort methods alphabetically
                sorted_methods = sorted(set(m['name'] for m in methods))

                for method_name in sorted_methods:
                    # Find coverage status (if any of the same-named methods are covered)
                    is_covered = any(m['name'] == method_name and m['covered'] for m in methods)

                    total_methods += 1
                    if is_covered:
                        covered_methods += 1
                        f.write(f"- [x] {method_name}\n")
                    else:
                        f.write(f"- [ ] {method_name}\n")

                f.write("\n")

            # Add summary
            if total_methods > 0:
                coverage_rate = (covered_methods / total_methods) * 100
                f.write(f"## 覆盖率统计\n\n")
                f.write(f"- 总方法数: {total_methods}\n")
                f.write(f"- 已覆盖: {covered_methods}\n")
                f.write(f"- 覆盖率: {coverage_rate:.2f}%\n")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Generate FUZZ coverage report from LLVM profdata'
    )
    parser.add_argument(
        '--fuzzer-bin',
        default=os.environ.get('FUZZER_BIN',
            './out/cmake/bin/companion_device_auth_services_fuzzer'),
        help='Path to fuzzer binary'
    )
    parser.add_argument(
        '--profdata',
        default=os.environ.get('PROFDATA',
            './out/cmake/coverage/default.profdata'),
        help='Path to merged profdata file'
    )
    parser.add_argument(
        '--services-dir',
        default=os.environ.get('SERVICES_DIR',
            '../../../services'),
        help='Path to services directory'
    )
    parser.add_argument(
        '--output',
        default='./out/cmake/coverage/method_coverage_report.md',
        help='Output markdown file'
    )

    args = parser.parse_args()

    # Convert to absolute paths
    script_dir = Path(__file__).parent.resolve()
    fuzzer_bin = Path(args.fuzzer_bin)
    if not fuzzer_bin.is_absolute():
        fuzzer_bin = script_dir / fuzzer_bin

    profdata = Path(args.profdata)
    if not profdata.is_absolute():
        profdata = script_dir / profdata

    services_dir = Path(args.services_dir)
    if not services_dir.is_absolute():
        services_dir = script_dir / services_dir

    output_file = Path(args.output)
    if not output_file.is_absolute():
        output_file = script_dir / output_file

    # Validate files exist
    if not fuzzer_bin.exists():
        print(f"Error: Fuzzer binary not found: {fuzzer_bin}", file=sys.stderr)
        sys.exit(1)

    if not profdata.exists():
        print(f"Error: Profdata file not found: {profdata}", file=sys.stderr)
        sys.exit(1)

    if not services_dir.exists():
        print(f"Error: Services directory not found: {services_dir}", file=sys.stderr)
        sys.exit(1)

    # Create output directory
    output_file.parent.mkdir(parents=True, exist_ok=True)

    # Generate report
    print(f"Generating coverage report...")
    print(f"  Fuzzer: {fuzzer_bin}")
    print(f"  Profdata: {profdata}")
    print(f"  Services: {services_dir}")
    print(f"  Output: {output_file}")

    analyzer = CoverageAnalyzer(
        str(fuzzer_bin),
        str(profdata),
        str(services_dir),
        str(output_file)
    )
    analyzer.generate_report()

    if output_file.exists():
        print(f"✓ Coverage report generated: {output_file}")
    else:
        print(f"✗ Failed to generate coverage report", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
