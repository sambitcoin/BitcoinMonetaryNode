# minimal stand-in so the daemon's own logic can be tested in isolation
def strip_block(raw, height, a, b):
    return b"", {}
def merkle_root(t):
    return b""
