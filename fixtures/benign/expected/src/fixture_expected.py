with open("/tmp/biodrift_benign_expected.txt", "w") as f:
    f.write("expected")

with open("/tmp/biodrift_benign_expected.txt", "r") as f:
    f.read()