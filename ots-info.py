#!/usr/bin/env python3

from opentimestamps.core.serialize import StreamDeserializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile
import sys

path = sys.argv[1]

with open(path, "rb") as fo:
    serialized = fo
    ctx = StreamDeserializationContext(serialized)
    file_stamp = DetachedTimestampFile.deserialize(ctx)
    print("File hash:", file_stamp.timestamp.msg.hex())
    print("Timestamp:\n", file_stamp.timestamp.str_tree(verbosity=0))
