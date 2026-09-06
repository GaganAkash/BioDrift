with open("/tmp/biodrift_benign_config.txt", "w") as f:
    f.write("benign")

with open("/tmp/biodrift_benign_config.txt", "r") as f:
    f.read()