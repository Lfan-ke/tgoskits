import sys
import json, re, collections, textwrap

d = [{'k': i} for i in range(2000)]
s = json.dumps(d)
assert re.match(r'^\[', s) and len(d) == 2000
print('IMPORT-OK', len(s))
sys.stdout.flush()
