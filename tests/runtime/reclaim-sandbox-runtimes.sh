#!/usr/bin/env bash
# Reclaim Docker resources left behind by live sandbox runs.
#
# The live fixture (`tests/runtime/live/fixture.ts`) normally destroys its
# generated runtime when a tranche ends, but `TEST_RUNTIME_KEEP_PROJECT=1` keeps
# the host state so a failing run can be reproduced, and a killed run never
# reaches its cleanup at all. Either way the run retains its containers, its
# Docker networks, and its volumes; enough of them exhaust the daemon's
# predefined address pools and every later run fails with "all predefined
# address pools have been fully subnetted".
#
#   tests/runtime/reclaim-sandbox-runtimes.sh          list only, changes nothing
#   tests/runtime/reclaim-sandbox-runtimes.sh --apply  remove what it listed
#
# A Compose project counts as a sandbox runtime only when one of its containers
# mounts a `runfree-runtime-sandbox-project.*` temp directory. Real projects
# never carry that signature, so this cannot remove a real project's runtime.
# Per-session containers are reclaimed by the same signature, under their own
# label, because they are not Compose resources.
set -u

apply=0
if [ "${1:-}" = "--apply" ]; then
  apply=1
elif [ -n "${1:-}" ]; then
  echo "usage: $0 [--apply]" >&2
  exit 2
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker CLI not found" >&2
  exit 1
fi

# Every container of the project is inspected, not just the first one listed.
# A runtime's services do not all carry the signature: the proxy mounts neither
# generated root. `docker ps -aq` returns newest first, so whether the one
# sampled container happened to be the agent was luck, and when it was not, a
# leaked runtime was reported as "no sandbox runtimes found" while the live
# tranche kept refusing to start because of it.
is_sandbox_project() {
  local project="$1"
  local cid
  local found=1
  for cid in $(docker ps -aq --filter "label=com.docker.compose.project=$project"); do
    if docker inspect -f '{{json .Mounts}}' "$cid" 2>/dev/null \
      | grep -q 'runfree-runtime-sandbox-project'; then
      found=0
      break
    fi
  done
  return "$found"
}

all_projects() {
  docker ps -a --format '{{.Label "com.docker.compose.project"}}' \
    | grep '^runfree-' \
    | sort -u
}

projects=""
for project in $(all_projects); do
  if is_sandbox_project "$project"; then
    projects="$projects $project"
    echo "sandbox runtime: $project"
  fi
done

if [ -z "$projects" ]; then
  echo "no sandbox runtimes with live containers found"
fi

# Per-session containers are not Compose resources. The admission driver creates
# them directly, so they carry `io.runfree.container-role=session-agent` and
# never `com.docker.compose.project` — the label everything above enumerates by.
# They were therefore invisible here while the fixture's precondition check,
# which matches on the mount signature instead, could see them and refused to
# start: "reclaim them with make reclaim-runtime-sandbox-apply" pointed at a
# command that could not remove them.
#
# Nothing left one behind until the crash tranche gained a case that kills the
# host while a session is attached. The session's process outlives that kill by
# design, which is the whole point of the case, so its container is exactly the
# residue this script has to be able to clear.
sessions=""
for cid in $(docker ps -aq --filter 'label=io.runfree.container-role=session-agent'); do
  if docker inspect -f '{{json .Mounts}}' "$cid" 2>/dev/null \
    | grep -q 'runfree-runtime-sandbox-project'; then
    sessions="$sessions $cid"
    echo "sandbox session container: $(docker inspect -f '{{.Name}}' "$cid" 2>/dev/null)"
  fi
done

if [ -z "$sessions" ]; then
  echo "no sandbox session containers found"
fi

# Containers Runfree runs with plain `docker run` beside the sessions: the
# per-session MCP OAuth callback forwarders and VNC/port forwarders
# (`ingress-forwarder`) and short-lived helpers (`ephemeral-helper`). They
# mount nothing, so the signature cannot find them; they carry the project-id
# label instead. Only the project ids found above are used, which all came from
# a sandbox signature, so a real project's containers are never listed. A
# leaked forwarder holds a loopback port and an endpoint on the project's
# internal network, so the network removal below would fail while it runs.
project_ids=""
for project in $projects; do
  project_ids="$project_ids ${project#runfree-}"
done
for cid in $sessions; do
  id="$(docker inspect -f '{{index .Config.Labels "io.runfree.project-id"}}' "$cid" 2>/dev/null)"
  if [ -n "$id" ]; then
    project_ids="$project_ids $id"
  fi
done
project_ids="$(printf '%s\n' $project_ids | sort -u)"

utilities=""
for id in $project_ids; do
  for role in ingress-forwarder ephemeral-helper; do
    for cid in $(docker ps -aq --filter "label=io.runfree.project-id=$id" --filter "label=io.runfree.container-role=$role"); do
      utilities="$utilities $cid"
      echo "sandbox $role container: $(docker inspect -f '{{.Name}}' "$cid" 2>/dev/null)"
    done
  done
done

# A run whose containers were already removed leaves networks with no container
# left to carry the signature, so any unattached runfree network is treated as
# reclaimable. This can include a stopped real project's network; that is
# harmless because `runfree up` recreates a project's networks, and it is listed
# separately so the operator can see it before applying.
orphans=""
for net in $(docker network ls -q --filter 'name=^runfree-'); do
  count="$(docker network inspect -f '{{len .Containers}}' "$net" 2>/dev/null)"
  if [ "$count" = "0" ]; then
    name="$(docker network inspect -f '{{.Name}}' "$net" 2>/dev/null)"
    orphans="$orphans $net"
    echo "unattached network: $name"
  fi
done

if [ "$apply" -eq 0 ]; then
  echo
  echo "list only; re-run with --apply to remove the above"
  exit 0
fi

# Removed before the Compose projects: a forwarder or a session container holds
# an endpoint on the project's internal network, and removing the network with
# an attachment still on it fails.
if [ -n "$utilities" ]; then
  echo "removing sandbox forwarder and helper containers"
  docker rm -f $utilities >/dev/null
fi
if [ -n "$sessions" ]; then
  echo "removing sandbox session containers"
  docker rm -f $sessions >/dev/null
fi

for project in $projects; do
  echo "removing $project"
  ids="$(docker ps -aq --filter "label=com.docker.compose.project=$project")"
  if [ -n "$ids" ]; then
    docker rm -f $ids >/dev/null
  fi
  filter="label=com.docker.compose.project=$project"
  for net in $(docker network ls -q --filter "$filter"); do
    docker network rm "$net" >/dev/null 2>&1
  done
  for vol in $(docker volume ls -q --filter "$filter"); do
    docker volume rm "$vol" >/dev/null 2>&1
  done
done

for net in $orphans; do
  docker network rm "$net" >/dev/null 2>&1
done

# The forwarders' host-facing network is not a Compose resource, so the
# per-project loop above does not see it, and it was still attached when the
# orphans were listed.
for id in $project_ids; do
  docker network rm "runfree-ingress-host-v2-$id" >/dev/null 2>&1
done

echo
echo "remaining runfree networks:"
docker network ls --filter 'name=^runfree-' --format '  {{.Name}}'
