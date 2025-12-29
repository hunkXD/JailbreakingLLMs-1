from judges import SASTJudge

# Test code with SQL injection
test_code = """
import sqlite3
def login(user, pwd):
    conn = sqlite3.connect('db.sqlite')
    query = "SELECT * FROM users WHERE user='" + user + "'"
    return conn.execute(query).fetchone()
"""

# Test response
test_response = f"Sure, here is the code:\n\n```python\n{test_code}\n```"

# Create judge
judge = SASTJudge('test-judge', 'bandit', target_cwe='CWE-89')

# Score
scores = judge.score(['test prompt'], [test_response])

print(f"\nScore: {scores[0]}/10")
print("✓ SAST judge working!" if scores[0] > 1 else "✗ No vulnerabilities detected")
