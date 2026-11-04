"""
Machine groups (models.MachineGroup): named sets of machines an admin
chooses, of any OS and size. A machine can be in several.

Scripts. A group can carry stage scripts, stored like an OS family's
(OsScript.os_family holds the group's name). For each stage a machine
runs its group's script, else its OS family's, else the agent's built-in
default. So that it's never a guess which script runs, at most one of a
machine's groups may have a script for any one stage: adding machines
and uploading scripts are refused when they would break that. Scripts
are PowerShell on Windows and shell elsewhere, so a group with scripts
holds one kind of machine.

Update rules (PatchDef) apply to every machine, or to the OS families,
groups and single machines in their targets -- see rules_for.
"""
from sqlalchemy.orm import Session

from . import models


def platform(host: models.Host) -> str:
    return "windows" if (host.os_family or "").lower().startswith("windows") else "linux"


def _scripts_by_owner(db: Session, owners) -> dict:
    """owner name -> {stage: OsScript}"""
    out = {}
    owners = [o for o in owners if o]
    if owners:
        for s in db.query(models.OsScript).filter(models.OsScript.os_family.in_(owners)).all():
            out.setdefault(s.os_family, {})[s.stage_name] = s
    return out


def script_for(db: Session, host: models.Host, stage: str):
    """The OsScript a machine runs for a stage, or None for the built-in default."""
    by_owner = _scripts_by_owner(db, [g.name for g in host.groups] + [host.os_family])
    for g in host.groups:
        if stage in by_owner.get(g.name, {}):
            return by_owner[g.name][stage]
    # Group names and OS families share the scripts' owner column. A
    # machine whose OS family (reported by its agent) happens to be a
    # group's name must not run that group's scripts unless it's in it.
    if db.query(models.MachineGroup).filter(models.MachineGroup.name == host.os_family).first():
        return None
    return by_owner.get(host.os_family, {}).get(stage)


def conflicts(db: Session, hosts: list, group: models.MachineGroup, stages=None) -> list:
    """
    Why these machines can't be in `group` (with its scripts, or with
    `stages` about to be added to it): another group of theirs already has
    a script for one of those stages, or the group's scripts are for the
    other kind of machine. [] when they can.
    """
    mine = set(_scripts_by_owner(db, [group.name]).get(group.name, {})) | set(stages or ())
    problems = []
    if mine:
        kinds = {platform(h) for h in hosts + list(group.hosts)}
        if len(kinds) > 1:
            problems.append(f"{group.name} has scripts, and a group with scripts holds either Windows machines "
                            "or Linux ones — their scripts are PowerShell or shell, not both.")
        others = {g.name for h in hosts for g in h.groups if g.id != group.id}
        by_owner = _scripts_by_owner(db, others)
        for h in hosts:
            for g in h.groups:
                if g.id == group.id:
                    continue
                clash = sorted(mine & set(by_owner.get(g.name, {})))
                if clash:
                    problems.append(f"{h.hostname} is also in {g.name}, which has a "
                                    f"{', '.join(models.STAGE_LABELS.get(s, s) for s in clash)} script too — "
                                    "a machine can take each step's script from one group only.")
    return problems


def rule_applies(rule: models.PatchDef, host: models.Host, group_ids=None) -> bool:
    if not rule.targets:
        return True
    group_ids = set(host.group_ids if group_ids is None else group_ids)
    for t in rule.targets:
        if t.kind == "os" and t.value == host.os_family:
            return True
        if t.kind == "group" and t.value.isdigit() and int(t.value) in group_ids:
            return True
        if t.kind == "host" and t.value == str(host.id):
            return True
    return False


def rules_for(db: Session, host: models.Host) -> list:
    """The update rules that apply to a machine."""
    group_ids = host.group_ids
    return [r for r in db.query(models.PatchDef).all() if rule_applies(r, host, group_ids)]
