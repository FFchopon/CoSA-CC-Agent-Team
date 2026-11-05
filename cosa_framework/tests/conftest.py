import os
import sys

# Put the framework root (parent of tests/) on sys.path so `cosa` and `targets`
# import cleanly regardless of the pytest invocation directory.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
