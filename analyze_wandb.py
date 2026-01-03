#!/usr/bin/env python3
"""
Analyze WandB export CSV and scan code with Bandit
"""

import pandas as pd
import subprocess
import json
import tempfile
import os
import re
from pathlib import Path


class WandBBanditAnalyzer:
    """Analyze WandB export and run Bandit on generated code"""

    def __init__(self, csv_path):
        """
        Initialize analyzer

        Args:
            csv_path: Path to WandB export CSV
        """
        self.csv_path = csv_path
        self.df = pd.read_csv(csv_path)
        self.results = []

        print(f"[INIT] Loaded {len(self.df)} rows from {csv_path}")

    def extract_code(self, text):
        """
        Extract Python code from text

        Args:
            text: Response text that may contain code

        Returns:
            Extracted code or None
        """
        if pd.isna(text):
            return None

        text = str(text)

        # Try to extract from markdown code blocks
        patterns = [
            r'```python\n(.*?)```',
            r'```py\n(.*?)```',
            r'```\n(.*?)```',
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.DOTALL)
            if match:
                code = match.group(1).strip()
                if self.looks_like_code(code):
                    return code

        # Check if entire text looks like code
        if self.looks_like_code(text):
            return text.strip()

        return None

    def looks_like_code(self, text):
        """Check if text looks like Python code"""
        code_indicators = [
            'def ',
            'class ',
            'import ',
            'from ',
            'if __name__',
            'print(',
            'return ',
        ]
        return any(indicator in text for indicator in code_indicators)

    def run_bandit(self, code):
        """
        Run Bandit on code

        Args:
            code: Python code to analyze

        Returns:
            Dict with Bandit results
        """
        # Save code to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            temp_file = f.name

        try:
            # Run Bandit
            result = subprocess.run(
                ['bandit', '-r', temp_file, '-f', 'json'],
                capture_output=True,
                text=True,
                timeout=30
            )

            # Parse JSON output
            bandit_output = json.loads(result.stdout)

            # Extract findings
            findings = bandit_output.get('results', [])

            # Count by severity
            severity_counts = {
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0
            }

            for finding in findings:
                severity = finding.get('issue_severity', 'UNKNOWN')
                if severity in severity_counts:
                    severity_counts[severity] += 1

            return {
                'success': True,
                'total_findings': len(findings),
                'severity_counts': severity_counts,
                'findings': findings,
                'error': None
            }

        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Timeout',
                'total_findings': 0,
                'severity_counts': {},
                'findings': []
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'total_findings': 0,
                'severity_counts': {},
                'findings': []
            }
        finally:
            # Cleanup temp file
            try:
                os.unlink(temp_file)
            except:
                pass

    def analyze_all(self):
        """Analyze all rows in the CSV"""
        print(f"\n{'=' * 70}")
        print("ANALYZING WANDB EXPORT WITH BANDIT")
        print(f"{'=' * 70}\n")

        code_found_count = 0

        for idx, row in self.df.iterrows():
            print(f"\n[Row {idx + 1}/{len(self.df)}]")

            # Extract code from target_response
            code = self.extract_code(row['target_response'])

            if not code:
                print("  ✗ No code found in response")
                self.results.append({
                    'row_index': idx,
                    'iteration': row.get('iter', ''),
                    'conv_num': row.get('conv_num', ''),
                    'prompt': row.get('prompt', '')[:100] + '...',
                    'has_code': False,
                    'bandit_results': None
                })
                continue

            code_found_count += 1
            print(f"  ✓ Code found ({len(code)} chars)")

            # Save code to file for inspection
            output_dir = Path('extracted_code')
            output_dir.mkdir(exist_ok=True)

            code_filename = output_dir / f"code_row{idx}_iter{row.get('iter', 'NA')}_conv{row.get('conv_num', 'NA')}.py"
            with open(code_filename, 'w') as f:
                f.write(code)
            print(f"  → Saved to: {code_filename}")

            # Run Bandit
            print(f"  → Running Bandit...")
            bandit_results = self.run_bandit(code)

            if bandit_results['success']:
                findings = bandit_results['total_findings']
                severity = bandit_results['severity_counts']

                print(f"  → Findings: {findings}")
                print(f"    - HIGH: {severity.get('HIGH', 0)}")
                print(f"    - MEDIUM: {severity.get('MEDIUM', 0)}")
                print(f"    - LOW: {severity.get('LOW', 0)}")

                # Show top findings
                for i, finding in enumerate(bandit_results['findings'][:3]):
                    print(f"    [{i + 1}] {finding.get('issue_severity')}: {finding.get('issue_text')}")
            else:
                print(f"  ✗ Bandit failed: {bandit_results['error']}")

            # Store results
            self.results.append({
                'row_index': idx,
                'iteration': row.get('iter', ''),
                'conv_num': row.get('conv_num', ''),
                'judge_score': row.get('judge_scores', ''),
                'prompt': row.get('prompt', '')[:100] + '...',
                'has_code': True,
                'code_length': len(code),
                'bandit_results': bandit_results,
                'code_file': str(code_filename)
            })

        print(f"\n{'=' * 70}")
        print(f"ANALYSIS COMPLETE")
        print(f"{'=' * 70}")
        print(f"Total rows: {len(self.df)}")
        print(f"Code found: {code_found_count}")
        print(f"No code: {len(self.df) - code_found_count}")

        return self.results

    def generate_summary_report(self):
        """Generate summary report"""
        print(f"\n{'=' * 70}")
        print("SUMMARY REPORT")
        print(f"{'=' * 70}\n")

        # Count rows with vulnerabilities
        rows_with_vulns = sum(
            1 for r in self.results
            if r.get('has_code') and
            r.get('bandit_results', {}).get('total_findings', 0) > 0
        )

        rows_with_code = sum(1 for r in self.results if r.get('has_code'))

        print(f"Rows with code: {rows_with_code}")
        print(f"Rows with vulnerabilities: {rows_with_vulns}")

        if rows_with_code > 0:
            print(f"Vulnerability rate: {rows_with_vulns / rows_with_code * 100:.1f}%")

        # Aggregate severity counts
        total_high = 0
        total_medium = 0
        total_low = 0

        for r in self.results:
            if r.get('has_code') and r.get('bandit_results'):
                severity = r['bandit_results'].get('severity_counts', {})
                total_high += severity.get('HIGH', 0)
                total_medium += severity.get('MEDIUM', 0)
                total_low += severity.get('LOW', 0)

        print(f"\nTotal findings across all code:")
        print(f"  - HIGH: {total_high}")
        print(f"  - MEDIUM: {total_medium}")
        print(f"  - LOW: {total_low}")
        print(f"  - TOTAL: {total_high + total_medium + total_low}")

        # Show most vulnerable code
        print(f"\n{'─' * 70}")
        print("TOP 5 MOST VULNERABLE CODE:")
        print(f"{'─' * 70}")

        # Sort by number of findings
        sorted_results = sorted(
            [r for r in self.results if r.get('has_code')],
            key=lambda x: x.get('bandit_results', {}).get('total_findings', 0),
            reverse=True
        )

        for i, r in enumerate(sorted_results[:5]):
            bandit = r.get('bandit_results', {})
            print(f"\n{i + 1}. Row {r['row_index']} (Iter {r['iteration']}, Conv {r['conv_num']})")
            print(f"   Judge Score: {r.get('judge_score', 'N/A')}")
            print(f"   Findings: {bandit.get('total_findings', 0)}")
            print(f"   Severity: HIGH={bandit.get('severity_counts', {}).get('HIGH', 0)}, "
                  f"MEDIUM={bandit.get('severity_counts', {}).get('MEDIUM', 0)}, "
                  f"LOW={bandit.get('severity_counts', {}).get('LOW', 0)}")
            print(f"   File: {r.get('code_file', 'N/A')}")
            print(f"   Prompt: {r.get('prompt', 'N/A')[:80]}...")

    def save_results(self, output_file='bandit_analysis_results.json'):
        """Save results to JSON file"""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)

        print(f"\n[SAVED] Results saved to: {output_file}")

    def create_csv_report(self, output_file='bandit_analysis_summary.csv'):
        """Create CSV summary report"""
        summary_data = []

        for r in self.results:
            if not r.get('has_code'):
                continue

            bandit = r.get('bandit_results', {})
            severity = bandit.get('severity_counts', {})

            summary_data.append({
                'Row': r['row_index'],
                'Iteration': r['iteration'],
                'Conv_Num': r['conv_num'],
                'Judge_Score': r.get('judge_score', ''),
                'Has_Code': r['has_code'],
                'Code_Length': r.get('code_length', 0),
                'Total_Findings': bandit.get('total_findings', 0),
                'High_Severity': severity.get('HIGH', 0),
                'Medium_Severity': severity.get('MEDIUM', 0),
                'Low_Severity': severity.get('LOW', 0),
                'Code_File': r.get('code_file', '')
            })

        df_summary = pd.DataFrame(summary_data)
        df_summary.to_csv(output_file, index=False)

        print(f"[SAVED] CSV report saved to: {output_file}")

        return df_summary


def main():
    import sys

    if len(sys.argv) < 2:
        print("Usage: python analyze_wandb_bandit.py <wandb_export.csv>")
        print("\nExample:")
        print("  python analyze_wandb_bandit.py wandb_export_20251206T17_01_04.72201_00.csv")
        sys.exit(1)

    csv_path = sys.argv[1]

    if not os.path.exists(csv_path):
        print(f"Error: File not found: {csv_path}")
        sys.exit(1)

    # Check if Bandit is installed
    try:
        subprocess.run(['bandit', '--version'], capture_output=True, check=True)
    except:
        print("Error: Bandit is not installed")
        print("Install with: pip install bandit")
        sys.exit(1)

    # Run analysis
    analyzer = WandBBanditAnalyzer(csv_path)
    results = analyzer.analyze_all()

    # Generate reports
    analyzer.generate_summary_report()
    analyzer.save_results()
    analyzer.create_csv_report()

    print("\n" + "=" * 70)
    print("NEXT STEPS:")
    print("=" * 70)
    print("1. Check extracted_code/ directory for all code files")
    print("2. Review bandit_analysis_results.json for detailed findings")
    print("3. Open bandit_analysis_summary.csv in Excel/LibreOffice")
    print("4. Run Bandit manually on specific files:")
    print("   bandit extracted_code/code_row0_*.py -f json")


if __name__ == "__main__":
    main()