"""Human-in-the-loop console: review pending block plans and manual-review cases.

Run:  python review_cli.py
"""
import time

from tools.review_service import ReviewService


def parse_selection(text: str, candidates: list) -> list:
    """'' -> all domains, 'n' -> none, '1,3' -> those numbers (invalid numbers are ignored)."""
    text = text.strip().lower()
    if text == "":
        return list(candidates)
    if text in ("n", "none"):
        return []
    picked = []
    for part in text.split(","):
        part = part.strip()
        if part.isdigit() and 1 <= int(part) <= len(candidates):
            picked.append(candidates[int(part) - 1])
    return picked


def show_plan(plan: dict) -> None:
    print("\n" + "=" * 72)
    print(f"{plan['plan_id']}   risk: {plan['overall_risk']}   email: {plan['email_id']}")
    print(f"From    : {plan['sender']['address']}")
    print(f"Subject : {plan['subject']}")
    print(f"Summary : {plan['summary']}")
    print("Proposed actions:")
    for i, a in enumerate(plan["proposed_actions"], 1):
        print(f"  {i}. {a['action']:<20} {a['target']}  [{a['risk_level']}, {a['evidence']['malicious']} malicious]")


def reject_flow(service: ReviewService, path, plan: dict, review_sec=None) -> None:
    reason = input("Reason (optional): ").strip()
    candidates = sorted({a["domain"] for a in plan["proposed_actions"] if a.get("domain")})
    domains = []
    if candidates:
        print("Domains you can add to the Safe List (false positives):")
        for i, d in enumerate(candidates, 1):
            print(f"  {i}. {d}")
        domains = parse_selection(input("Add to Safe List [Enter = all, numbers like 1,2, n = none]: "), candidates)
    result = service.reject(path, reason, domains, review_sec=review_sec)
    added = result["human_decision"]["safe_list_added"]
    print(f"Rejected. Added to Safe List: {', '.join(added) if added else 'nothing'}")


def review_pending(service: ReviewService, pending: list) -> bool:
    """Returns False if the admin chose to quit."""
    for path, plan in pending:
        show_plan(plan)
        shown = time.monotonic()  # decision time is measured from here until a / r is pressed
        while True:
            choice = input("\n[a]pprove  [r]eject  [s]kip  [q]uit > ").strip().lower()
            elapsed = time.monotonic() - shown
            if choice == "a":
                service.approve(path, input("Note (optional): ").strip(), review_sec=elapsed)
                print("Approved. Simulated firewall rules written to outputs/logs/firewall_sim.log")
                break
            if choice == "r":
                reject_flow(service, path, plan, elapsed)
                break
            if choice == "s":
                break
            if choice == "q":
                print("Bye.")
                return False
    return True


def show_manual(plan: dict) -> None:
    print("\n" + "=" * 72)
    print(f"{plan['plan_id']}   MANUAL REVIEW   email: {plan['email_id']}")
    print(f"Tag     : {plan['tag']}")
    print(f"From    : {plan['sender']['address']}")
    print(f"Subject : {plan['subject']}")
    print(f"Summary : {plan['summary']}")


def review_manual(service: ReviewService, queue: list) -> None:
    if not queue:
        return
    print(f"\n--- {len(queue)} email(s) need manual review (VirusTotal could not check them) ---")
    for path, plan in queue:
        show_manual(plan)
        shown = time.monotonic()
        while True:
            choice = input("\nAfter checking by hand: [t] confirmed threat  [s] confirmed safe  "
                           "[k] keep in queue  [q] quit > ").strip().lower()
            elapsed = time.monotonic() - shown
            if choice in ("t", "s"):
                verdict = "THREAT" if choice == "t" else "SAFE"
                service.resolve_manual(path, verdict, input("Note (optional): ").strip(), review_sec=elapsed)
                print(f"Closed as {verdict}. The employee reply is saved in outputs/notifications/")
                break
            if choice == "k":
                break
            if choice == "q":
                print("Bye.")
                return


def main() -> None:
    service = ReviewService()
    pending, manual = service.pending(), service.manual_queue()
    print(f"{len(pending)} plan(s) waiting for approval, {len(manual)} email(s) in Manual_Review.")

    if review_pending(service, pending):
        review_manual(service, service.manual_queue())
        print("\nDone. Decisions are in outputs/logs/audit_log.jsonl")


if __name__ == "__main__":
    main()
