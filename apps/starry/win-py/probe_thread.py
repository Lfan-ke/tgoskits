import sys, threading
r = []
def work(n):
    r.append(n * n)
ts = [threading.Thread(target=work, args=(i,)) for i in range(4)]
for t in ts: t.start()
for t in ts: t.join()
print('THREAD-OK', sorted(r)); sys.stdout.flush()
