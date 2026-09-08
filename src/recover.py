"""Read the actual merge result in a newly started process."""

import json
import os
import sys
from pathlib import Path
from src.github import GitHub


if __name__ == "__main__":
    token_dir = Path(os.environ.get("PROOF_TOKEN_DIR", ".local"))
    client = GitHub(json.loads((token_dir / "merger-token.json").read_text())["token"], "app:4873237")
    pull = client.pull(int(sys.argv[1]))
    result = {"merged": pull["merged"], "recovered": pull["merged"], "sha": pull["merge_commit_sha"],
              "head_matches": pull["head"]["sha"] == sys.argv[2],
              "mutation_count": sum(item["method"] != "GET" for item in client.history)}
    print(json.dumps(result))
