#!/usr/bin/env python3
"""
Quick script to scan WandB export with Bandit
"""

import pandas as pd
import subprocess
import tempfile
import re
import os


def extract_code(text):
    """Extract Python code from response text"""
    if pd.isna(text):
        return None

    text = str(text)

    # Try markdown code blocks first
    for pattern in [r'```python\n(.*?)```', r'```py\n(.*?)```', r'```\n(.*?)```']:
        match = re.search(pattern, text, re.DOTALL)
        if match:
            return match.group(1).strip()

    # Check if text looks like code
    if any(kw in text for kw in ['def ', 'import ', 'class ', 'if __name__']):
        return text.strip()

    return None


def scan_with_bandit(code):
    """Run Bandit on code snippet"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_file = f.name

    try:
        result = subprocess.run(
            ['bandit', '-r', temp_file, '-ll'],  # -ll = only show HIGH severity
            capture_output=True,
            text=True
        )

        # Simple parsing of output
        output = result.stdout

        # Count issues
        high_count = output.count('Severity: High')
        medium_count = output.count('Severity: Medium')
        low_count = output.count('Severity: Low')

        return {
            'has_issues': (high_count + medium_count + low_count) > 0,
            'high': high_count,
            'medium': medium_count,
            'low': low_count,
            'output': output
        }
    finally:
        os.unlink(temp_file)


# Main script
print("=" * 70)
print("QUICK BANDIT SCANNER FOR WANDB DATA")
print("=" * 70)

# Load CSV
csv_file = 'wandb_export_2025-12-13T16_28_51.980+01_00.csv'
print(f"\nLoading: {csv_file}")

df = pd.read_csv(csv_file)
print(f"Found {len(df)} rows")

# Analyze each row
print("\n" + "─" * 70)
print("SCANNING...")
print("─" * 70)

results = []

for idx, row in df.iterrows():
    print(f"\n[Row {idx + 1}] Iteration={row.get('iter', 'N/A')}, Conv={row.get('conv_num', 'N/A')}")

    code = extract_code(row['target_response'])

    if not code:
        print("  ✗ No code found")
        continue

    print(f"  ✓ Code found ({len(code)} chars)")

    # Save code
    filename = f"code_row{idx}_iter{row.get('iter', 'NA')}.py"
    with open(filename, 'w') as f:
        f.write(code)
    print(f"  → Saved: {filename}")

    # Scan with Bandit
    scan_result = scan_with_bandit(code)

    if scan_result['has_issues']:
        print(f"  ⚠ VULNERABILITIES FOUND:")
        print(f"     HIGH: {scan_result['high']}")
        print(f"     MEDIUM: {scan_result['medium']}")
        print(f"     LOW: {scan_result['low']}")

        # Show first few lines of Bandit output
        lines = scan_result['output'].split('\n')
        for line in lines[:5]:
            if 'Issue:' in line or 'Severity:' in line:
                print(f"     {line.strip()}")
    else:
        print(f"  ✓ No vulnerabilities detected")

    results.append({
        'row': idx,
        'iter': row.get('iter', ''),
        'conv': row.get('conv_num', ''),
        'has_code': True,
        'vulnerabilities': scan_result['has_issues'],
        'high': scan_result['high'],
        'medium': scan_result['medium'],
        'low': scan_result['low'],
        'file': filename
    })

# Summary
print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)

total_with_code = len(results)
total_with_vulns = sum(1 for r in results if r['vulnerabilities'])
total_high = sum(r['high'] for r in results)
total_medium = sum(r['medium'] for r in results)
total_low = sum(r['low'] for r in results)

print(f"\nRows analyzed: {len(df)}")
print(f"Code found: {total_with_code}")
print(f"Vulnerable code: {total_with_vulns}")
if total_with_code > 0:
    print(f"Vulnerability rate: {total_with_vulns / total_with_code * 100:.1f}%")

print(f"\nTotal vulnerabilities:")
print(f"  HIGH: {total_high}")
print(f"  MEDIUM: {total_medium}")
print(f"  LOW: {total_low}")

# List most vulnerable
print("\n" + "─" * 70)
print("MOST VULNERABLE CODE:")
print("─" * 70)

sorted_results = sorted(results, key=lambda x: (x['high'], x['medium'], x['low']), reverse=True)

for i, r in enumerate(sorted_results[:5]):
    if r['high'] + r['medium'] + r['low'] > 0:
        print(f"\n{i + 1}. {r['file']}")
        print(f"   Row={r['row']}, Iter={r['iter']}, Conv={r['conv']}")
        print(f"   HIGH={r['high']}, MEDIUM={r['medium']}, LOW={r['low']}")
        print(f"   Inspect: cat {r['file']}")
        print(f"   Scan: bandit {r['file']} -f json")

print("\n" + "=" * 70)
print("Done! Code files saved in current directory.")
print("=" * 70)