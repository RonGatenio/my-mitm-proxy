"""Parse a text/event-stream body (the SSE line format) into events.

Feed the already-dechunked HTTP response body (dumpparse.http1 first). A blank
line dispatches an event; lines starting with ':' are comments; 'field: value'
lines accumulate. 'data' fields join with '\\n'. A block that carries only
comments (no field) is not dispatched as an event.
"""
from typing import List, Dict


def parse_events(body: bytes) -> List[Dict]:
    text = body.decode("utf-8", "replace")
    events: List[Dict] = []
    cur = {"event": None, "data": [], "id": None, "retry": None, "comments": []}

    def flush():
        has_field = bool(cur["data"] or cur["event"] or cur["id"] or cur["retry"])
        if has_field:
            events.append({"event": cur["event"], "data": "\n".join(cur["data"]),
                           "id": cur["id"], "retry": cur["retry"],
                           "comments": list(cur["comments"])})
        cur.update(event=None, data=[], id=None, retry=None, comments=[])

    for raw in text.split("\n"):
        line = raw.rstrip("\r")
        if line == "":
            flush(); continue
        if line.startswith(":"):
            cur["comments"].append(line[1:]); continue
        if ":" in line:
            field, val = line.split(":", 1)
            if val.startswith(" "):
                val = val[1:]
        else:
            field, val = line, ""
        if field == "data":
            cur["data"].append(val)
        elif field == "event":
            cur["event"] = val
        elif field == "id":
            cur["id"] = val
        elif field == "retry":
            cur["retry"] = val
    flush()
    return events
