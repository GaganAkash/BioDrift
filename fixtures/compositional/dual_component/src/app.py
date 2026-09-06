from persist import load, store

store("/tmp/biodrift_compositional.txt", "state")
data = load("/tmp/biodrift_compositional.txt")
print(f"read: {data}")