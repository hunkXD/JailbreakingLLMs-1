import sys
sys.path.insert(0, '.')

# Try to load a new model
from conversers import load_attack_and_target_models

# Test with a newer model
try:
    print("Testing gpt-4o...")
    attackLM, targetLM = load_attack_and_target_models(
        attack_model_name="gpt-3.5-turbo",
        target_model_name="gpt-4o"
    )
    print("✓ gpt-4o is supported!")
except Exception as e:
    print(f"✗ gpt-4o not supported: {e}")

try:
    print("\nTesting claude-3-5-sonnet...")
    attackLM, targetLM = load_attack_and_target_models(
        attack_model_name="gpt-3.5-turbo",
        target_model_name="claude-3-5-sonnet"
    )
    print("✓ claude-3-5-sonnet is supported!")
except Exception as e:
    print(f"✗ claude-3-5-sonnet not supported: {e}")
