"""
build_dataset.py
Generates eval_dataset.json: 30 labeled synthetic Windows Security 4625
(failed-logon) alert scenarios for evaluating Cortex-Chain's triage.

Each item is an *aggregated alert* of the kind Splunk would POST to the
/analyze-threat webhook: a summary of 4625 activity plus a couple of raw
sample events. Every item carries a ground-truth `label`:
    "brute_force"  -> genuine attack pattern
    "benign"       -> noise (typos, stale creds, lockouts, re-auth)

The discriminating signals mirror real triage:
    brute_force : high failure_count, 1 (or few) source IP, short window,
                  privileged/common target accounts, bad-password or
                  user-enumeration status codes.
    benign      : low failure_count, internal/known device, activity spread
                  over minutes-to-hours, often a success shortly after.

Two deliberately hard cases are included so the score is meaningful rather
than trivially 30/30:
    - case_07 : low-and-slow brute force (only 25 fails, but over 5 min,
                single external IP, all bad-password on 'administrator')
    - case_22 : benign caps-lock typo in a SHORT window (3 fails in 38s)
                -- tests that the model weighs COUNT, not just window length.
"""

import json

# Common 4625 status/substatus codes
BAD_PASSWORD = "0xC000006A"   # account exists, wrong password
NO_SUCH_USER = "0xC0000064"   # user name does not exist (enumeration)
LOCKED_OUT   = "0xC0000234"   # account locked
DISABLED     = "0xC0000072"   # account disabled


def ev(user, ip, status, logon_type=3, ws="WIN-CLIENT", domain="CORP", t="T"):
    """One raw 4625 record."""
    return {
        "EventID": 4625,
        "TargetUserName": user,
        "TargetDomainName": domain,
        "IpAddress": ip,
        "LogonType": logon_type,
        "WorkstationName": ws,
        "Status": "0xC000006D",
        "SubStatus": status,
        "TimeCreated": t,
    }


def case(cid, label, rule, **alert):
    alert.setdefault("rule", rule)
    return {"id": cid, "label": label, "alert": alert}


data = []

# ---------------------------------------------------------------- BRUTE FORCE
data.append(case("case_01", "brute_force", "Excessive 4625 - single source",
    target_account="administrator", distinct_source_ips=1,
    source_ips=["45.61.148.22"], failure_count=80, time_window_seconds=40,
    logon_type=3, dominant_substatus=BAD_PASSWORD,
    sample_events=[ev("administrator", "45.61.148.22", BAD_PASSWORD, ws="kali"),
                   ev("administrator", "45.61.148.22", BAD_PASSWORD, ws="kali")]))

data.append(case("case_02", "brute_force", "Username enumeration sweep",
    target_account="<many>", distinct_target_accounts=60, distinct_source_ips=1,
    source_ips=["185.220.101.4"], failure_count=120, time_window_seconds=90,
    logon_type=3, dominant_substatus=NO_SUCH_USER,
    sample_events=[ev("jsmith", "185.220.101.4", NO_SUCH_USER),
                   ev("oracle", "185.220.101.4", NO_SUCH_USER)]))

data.append(case("case_03", "brute_force", "RDP failed logons",
    target_account="administrator", distinct_source_ips=1,
    source_ips=["103.97.176.9"], failure_count=55, time_window_seconds=120,
    logon_type=10, dominant_substatus=BAD_PASSWORD,
    sample_events=[ev("administrator", "103.97.176.9", BAD_PASSWORD, 10, "hydra"),
                   ev("administrator", "103.97.176.9", BAD_PASSWORD, 10, "hydra")]))

data.append(case("case_04", "brute_force", "Service account hammering",
    target_account="svc-sql", distinct_source_ips=1,
    source_ips=["10.10.9.44"], failure_count=40, time_window_seconds=30,
    logon_type=3, dominant_substatus=BAD_PASSWORD,
    sample_events=[ev("svc-sql", "10.10.9.44", BAD_PASSWORD),
                   ev("svc-sql", "10.10.9.44", BAD_PASSWORD)]))

data.append(case("case_05", "brute_force", "Rapid privileged-account failures",
    target_account="domainadmin", distinct_source_ips=1,
    source_ips=["45.9.148.77"], failure_count=30, time_window_seconds=25,
    logon_type=3, dominant_substatus=BAD_PASSWORD,
    sample_events=[ev("domainadmin", "45.9.148.77", BAD_PASSWORD),
                   ev("domainadmin", "45.9.148.77", BAD_PASSWORD)]))

data.append(case("case_06", "brute_force", "Small-subnet distributed failures",
    target_account="root", distinct_source_ips=3,
    source_ips=["192.0.2.10", "192.0.2.11", "192.0.2.12"], failure_count=90,
    time_window_seconds=70, logon_type=3, dominant_substatus=BAD_PASSWORD,
    sample_events=[ev("root", "192.0.2.10", BAD_PASSWORD),
                   ev("root", "192.0.2.12", BAD_PASSWORD)]))

data.append(case("case_07", "brute_force", "Low-and-slow single-source",
    target_account="administrator", distinct_source_ips=1,
    source_ips=["91.219.236.18"], failure_count=25, time_window_seconds=300,
    logon_type=3, dominant_substatus=BAD_PASSWORD,
    note_for_reviewer="HARD: low count but sustained, external, privileged, all bad-password",
    sample_events=[ev("administrator", "91.219.236.18", BAD_PASSWORD),
                   ev("administrator", "91.219.236.18", BAD_PASSWORD)]))

data.append(case("case_08", "brute_force", "NTLM failure flood",
    target_account="Administrator", distinct_source_ips=1,
    source_ips=["45.155.205.233"], failure_count=200, time_window_seconds=100,
    logon_type=3, dominant_substatus=BAD_PASSWORD,
    sample_events=[ev("Administrator", "45.155.205.233", BAD_PASSWORD, ws="RANDOM7X"),
                   ev("Administrator", "45.155.205.233", BAD_PASSWORD, ws="ZZ19QP")]))

data.append(case("case_09", "brute_force", "After-hours admin failures",
    target_account="backup_admin", distinct_source_ips=1,
    source_ips=["194.165.16.71"], failure_count=60, time_window_seconds=45,
    logon_type=3, dominant_substatus=BAD_PASSWORD, time_of_day="03:14",
    sample_events=[ev("backup_admin", "194.165.16.71", BAD_PASSWORD, t="03:14:02"),
                   ev("backup_admin", "194.165.16.71", BAD_PASSWORD, t="03:14:05")]))

data.append(case("case_10", "brute_force", "Common-account spray from one host",
    target_account="administrator,admin,root,sa", distinct_target_accounts=4,
    distinct_source_ips=1, source_ips=["45.132.227.9"], failure_count=70,
    time_window_seconds=50, logon_type=3, dominant_substatus=BAD_PASSWORD,
    sample_events=[ev("admin", "45.132.227.9", BAD_PASSWORD),
                   ev("sa", "45.132.227.9", BAD_PASSWORD)]))

data.append(case("case_11", "brute_force", "Foreign RDP with lockout",
    target_account="jdoe", distinct_source_ips=1,
    source_ips=["27.124.5.98"], failure_count=45, time_window_seconds=90,
    logon_type=10, dominant_substatus=LOCKED_OUT,
    sample_events=[ev("jdoe", "27.124.5.98", BAD_PASSWORD, 10),
                   ev("jdoe", "27.124.5.98", LOCKED_OUT, 10)]))

data.append(case("case_12", "brute_force", "VPN account brute force",
    target_account="vpn-gw", distinct_source_ips=1,
    source_ips=["176.113.115.42"], failure_count=35, time_window_seconds=40,
    logon_type=3, dominant_substatus=BAD_PASSWORD,
    sample_events=[ev("vpn-gw", "176.113.115.42", BAD_PASSWORD),
                   ev("vpn-gw", "176.113.115.42", BAD_PASSWORD)]))

data.append(case("case_13", "brute_force", "DB 'sa' account flood",
    target_account="sa", distinct_source_ips=1,
    source_ips=["45.227.254.8"], failure_count=100, time_window_seconds=55,
    logon_type=3, dominant_substatus=BAD_PASSWORD,
    sample_events=[ev("sa", "45.227.254.8", BAD_PASSWORD),
                   ev("sa", "45.227.254.8", BAD_PASSWORD)]))

data.append(case("case_14", "brute_force", "Sustained domain-admin failures",
    target_account="da-svc", distinct_source_ips=1,
    source_ips=["193.32.162.20"], failure_count=50, time_window_seconds=60,
    logon_type=3, dominant_substatus=BAD_PASSWORD,
    sample_events=[ev("da-svc", "193.32.162.20", BAD_PASSWORD),
                   ev("da-svc", "193.32.162.20", BAD_PASSWORD)]))

data.append(case("case_15", "brute_force", "High-rate burst",
    target_account="administrator", distinct_source_ips=1,
    source_ips=["146.70.199.15"], failure_count=300, time_window_seconds=30,
    logon_type=3, dominant_substatus=BAD_PASSWORD,
    sample_events=[ev("administrator", "146.70.199.15", BAD_PASSWORD),
                   ev("administrator", "146.70.199.15", BAD_PASSWORD)]))

# ---------------------------------------------------------------------- BENIGN
data.append(case("case_16", "benign", "Single user typo then success",
    target_account="mgarcia", distinct_source_ips=1,
    source_ips=["10.0.4.31"], failure_count=3, time_window_seconds=120,
    logon_type=2, dominant_substatus=BAD_PASSWORD, followed_by_success=True,
    sample_events=[ev("mgarcia", "10.0.4.31", BAD_PASSWORD, 2, "MGARCIA-PC")]))

data.append(case("case_17", "benign", "Stale mobile device credential",
    target_account="rpatel", distinct_source_ips=1,
    source_ips=["10.0.7.88"], failure_count=5, time_window_seconds=1200,
    logon_type=3, dominant_substatus=BAD_PASSWORD, known_device=True,
    sample_events=[ev("rpatel", "10.0.7.88", BAD_PASSWORD, 3, "iPhone-rpatel")]))

data.append(case("case_18", "benign", "New employee mistyping",
    target_account="tnguyen", distinct_source_ips=1,
    source_ips=["10.0.4.52"], failure_count=4, time_window_seconds=600,
    logon_type=2, dominant_substatus=BAD_PASSWORD, followed_by_success=True,
    sample_events=[ev("tnguyen", "10.0.4.52", BAD_PASSWORD, 2, "TNGUYEN-PC")]))

data.append(case("case_19", "benign", "Service restart with old cached cred",
    target_account="svc-report", distinct_source_ips=1,
    source_ips=["10.10.2.5"], failure_count=2, time_window_seconds=15,
    logon_type=5, dominant_substatus=BAD_PASSWORD, followed_by_success=True,
    sample_events=[ev("svc-report", "10.10.2.5", BAD_PASSWORD, 5, "APPSRV01")]))

data.append(case("case_20", "benign", "Printer with outdated credentials",
    target_account="scan-svc", distinct_source_ips=1,
    source_ips=["10.0.9.200"], failure_count=6, time_window_seconds=28800,
    logon_type=3, dominant_substatus=BAD_PASSWORD, known_device=True,
    sample_events=[ev("scan-svc", "10.0.9.200", BAD_PASSWORD, 3, "HP-MFP-3F")]))

data.append(case("case_21", "benign", "Wrong-domain single failure then success",
    target_account="klee", distinct_source_ips=1,
    source_ips=["10.0.4.19"], failure_count=1, time_window_seconds=10,
    logon_type=2, dominant_substatus=BAD_PASSWORD, followed_by_success=True,
    sample_events=[ev("klee", "10.0.4.19", BAD_PASSWORD, 2, "KLEE-PC", domain="OLDDOM")]))

data.append(case("case_22", "benign", "Caps-lock typo, short window",
    target_account="dwilson", distinct_source_ips=1,
    source_ips=["10.0.4.77"], failure_count=3, time_window_seconds=38,
    logon_type=2, dominant_substatus=BAD_PASSWORD, followed_by_success=True,
    note_for_reviewer="HARD: short window like an attack, but only 3 fails from user's own PC",
    sample_events=[ev("dwilson", "10.0.4.77", BAD_PASSWORD, 2, "DWILSON-PC")]))

data.append(case("case_23", "benign", "Expired password after vacation",
    target_account="bthomas", distinct_source_ips=1,
    source_ips=["10.0.4.61"], failure_count=3, time_window_seconds=180,
    logon_type=2, dominant_substatus=BAD_PASSWORD, followed_by_success=True,
    sample_events=[ev("bthomas", "10.0.4.61", BAD_PASSWORD, 2, "BTHOMAS-PC")]))

data.append(case("case_24", "benign", "Scheduled task with rotated password",
    target_account="svc-batch", distinct_source_ips=1,
    source_ips=["10.10.2.9"], failure_count=4, time_window_seconds=900,
    logon_type=4, dominant_substatus=BAD_PASSWORD, known_device=True,
    sample_events=[ev("svc-batch", "10.10.2.9", BAD_PASSWORD, 4, "BATCHSRV")]))

data.append(case("case_25", "benign", "Two users one failure each",
    target_account="<mixed>", distinct_target_accounts=2, distinct_source_ips=2,
    source_ips=["10.0.4.33", "10.0.5.41"], failure_count=2,
    time_window_seconds=45, logon_type=2, dominant_substatus=BAD_PASSWORD,
    sample_events=[ev("achen", "10.0.4.33", BAD_PASSWORD, 2, "ACHEN-PC"),
                   ev("pmoore", "10.0.5.41", BAD_PASSWORD, 2, "PMOORE-PC")]))

data.append(case("case_26", "benign", "Mapped drive cached credential",
    target_account="hkim", distinct_source_ips=1,
    source_ips=["10.0.6.72"], failure_count=5, time_window_seconds=1800,
    logon_type=3, dominant_substatus=BAD_PASSWORD, known_device=True,
    sample_events=[ev("hkim", "10.0.6.72", BAD_PASSWORD, 3, "HKIM-PC")]))

data.append(case("case_27", "benign", "Email client after password change",
    target_account="lroberts", distinct_source_ips=1,
    source_ips=["10.0.7.14"], failure_count=4, time_window_seconds=3600,
    logon_type=3, dominant_substatus=BAD_PASSWORD, known_device=True,
    sample_events=[ev("lroberts", "10.0.7.14", BAD_PASSWORD, 3, "Outlook-Mobile")]))

data.append(case("case_28", "benign", "Admin typo from jump host then success",
    target_account="admin-jturner", distinct_source_ips=1,
    source_ips=["10.10.0.5"], failure_count=2, time_window_seconds=25,
    logon_type=10, dominant_substatus=BAD_PASSWORD, followed_by_success=True,
    known_device=True,
    sample_events=[ev("admin-jturner", "10.10.0.5", BAD_PASSWORD, 10, "JUMP01")]))

data.append(case("case_29", "benign", "Shared workstation occasional fails",
    target_account="<mixed>", distinct_target_accounts=3, distinct_source_ips=1,
    source_ips=["10.0.8.9"], failure_count=3, time_window_seconds=28800,
    logon_type=2, dominant_substatus=BAD_PASSWORD, known_device=True,
    sample_events=[ev("shift1", "10.0.8.9", BAD_PASSWORD, 2, "FLOOR-KIOSK"),
                   ev("shift2", "10.0.8.9", BAD_PASSWORD, 2, "FLOOR-KIOSK")]))

data.append(case("case_30", "benign", "Wi-Fi 802.1x re-auth failures",
    target_account="ewhite", distinct_source_ips=1,
    source_ips=["10.0.10.55"], failure_count=4, time_window_seconds=1500,
    logon_type=3, dominant_substatus=BAD_PASSWORD, known_device=True,
    sample_events=[ev("ewhite", "10.0.10.55", BAD_PASSWORD, 3, "ewhite-laptop")]))


if __name__ == "__main__":
    # sanity: balanced, unique ids
    ids = [c["id"] for c in data]
    assert len(ids) == len(set(ids)), "duplicate id"
    bf = sum(1 for c in data if c["label"] == "brute_force")
    bn = sum(1 for c in data if c["label"] == "benign")
    with open("eval_dataset.json", "w") as f:
        json.dump(data, f, indent=2)
    print(f"Wrote eval_dataset.json: {len(data)} cases ({bf} brute_force, {bn} benign)")
