#!/usr/bin/env python3
"""TC-1289: check primary and dstack metadata-action tags for push events."""

import re
from pathlib import Path


workflow = Path(__file__).resolve().parents[2] / ".github/workflows/docker.yml"
lines = workflow.read_text().splitlines()

def metadata_rules(index):
    start = [i for i, line in enumerate(lines)
             if line == "      - name: Extract metadata (tags, labels)"][index]
    disable_auto_latest = "          flavor: latest=false" in lines[start:start + 7]
    start = lines.index("          tags: |", start) + 1
    rules = []
    for line in lines[start:]:
        if not line.startswith("            "):
            break
        rules.append(dict(part.split("=", 1) for part in re.split(r",(?=[a-z]+=)", line.strip())))
    return rules, disable_auto_latest


def enabled(rule, ref, event):
    condition = rule.get("enable", "true")
    if condition == "true":
        return True
    if condition == "{{is_default_branch}}":
        return ref == "refs/heads/main"
    if condition.startswith("${{ ") and condition.endswith(" }}"):
        values = {"github.event_name": event, "github.ref": ref,
                  "steps.build_features.outputs.manual_version": ""}
        def evaluate(term):
            prefix = re.fullmatch(r"startsWith\(github\.ref, '([^']+)'\)", term)
            if prefix:
                return ref.startswith(prefix[1])
            comparison = re.fullmatch(r"([\w.]+) (==|!=) '([^']*)'", term)
            assert comparison, f"unrecognized metadata expression: {term}"
            left, op, right = comparison.groups()
            return values[left] == right if op == "==" else values[left] != right
        return all(evaluate(term) for term in condition[4:-3].split(" && "))
    raise AssertionError(f"unrecognized metadata enable rule: {condition}")


def tags_for(ref, rules, disable_auto_latest, event):
    tags = set()
    for rule in rules:
        if not enabled(rule, ref, event):
            continue
        kind = rule["type"]
        if kind == "sha":
            tags.add(rule.get("prefix", "").replace("${{ steps.build_features.outputs.sha_prefix }}",
                                                    "dstack-") + "13cbcdc")
        elif kind == "semver":
            if ref.startswith("refs/tags/v"):
                version = ref.removeprefix("refs/tags/v").split(".")
                tags.add(rule["pattern"].replace("{{version}}", ".".join(version))
                         .replace("{{major}}", version[0]).replace("{{minor}}", version[1])
                         + rule.get("suffix", "").replace(
                             "${{ steps.build_features.outputs.image_suffix }}", ""))
        elif kind == "raw":
            tags.add(rule["value"].replace("${{ steps.build_features.outputs.image_suffix }}", ""))
        else:
            raise AssertionError(f"unrecognized metadata tag type: {kind}")
    if ref.startswith("refs/tags/v") and not disable_auto_latest:
        tags.add("latest")  # metadata-action defaults to automatic latest for stable semver
    return tags


for index, event, ref, expected in (
    (0, "push", "refs/heads/main", {"main", "edge", "13cbcdc"}),
    (0, "push", "refs/tags/v1.20.6", {"1.20.6", "1.20", "1", "13cbcdc", "latest"}),
    (0, "release", "refs/tags/v1.20.6", {"1.20.6", "1.20", "1", "13cbcdc", "latest"}),
    (0, "workflow_dispatch", "refs/tags/v1.20.6",
     {"1.20.6", "1.20", "1", "13cbcdc"}),
    (1, "push", "refs/heads/main", {"dstack-main", "dstack-edge", "dstack-13cbcdc"}),
    (1, "push", "refs/tags/v1.20.6",
     {"1.20.6-dstack", "1.20-dstack", "1-dstack", "dstack-13cbcdc", "dstack"}),
    (1, "release", "refs/tags/v1.20.6",
     {"1.20.6-dstack", "1.20-dstack", "1-dstack", "dstack-13cbcdc", "dstack"}),
    (1, "workflow_dispatch", "refs/tags/v1.20.6",
     {"1.20.6-dstack", "1.20-dstack", "1-dstack", "dstack-13cbcdc"}),
):
    actual = tags_for(ref, *metadata_rules(index), event)
    assert actual == expected, f"build {index} {event} {ref}: expected {sorted(expected)}, got {sorted(actual)}"
    print(f"ok build {index} {event} {ref}: {', '.join(sorted(actual))}")
