"""Single-agent baseline vs our multi-agent pipeline: same emails, same VirusTotal evidence.

Run:  python compare_agents.py      (needs LLM_API_KEY in .env: both sides use the same LLM)
Result: outputs/reports/agent_comparison.json and agent_comparison.md

The single agent gets ONE prompt: the raw email plus the VirusTotal answers for every candidate the plain
regex found. In one pass it must pick the indicators, judge the risk and say what to block. It is not given
our thresholds, our guard rules or a human fallback. Whatever the numbers show goes into the report.
"""
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from agents.extractor_agent import ExtractorAgent
from config import Config
from evaluate import AccuracyEvaluator
from run_demo import ScenarioRunner
from tools.email_loader import EmailLoader
from tools.llm_factory import DEFAULT_MODELS
from tools.vt_client import VTClient, VTError

CAVEAT = ("Only 7 dummy emails, one run, mock VirusTotal answers written by us, and LLM answers can differ "
          "between runs. The single agent received the VirusTotal answers inside its prompt (it has no live tool). "
          "Read this as an indicative comparison, not a benchmark.")

SYSTEM_PROMPT = (
    "You are a security analyst. Work in ONE pass on a forwarded suspicious email: "
    "(1) list every real URL and IP address that is an indicator in the email, "
    "(2) using the VirusTotal evidence provided, decide the overall risk as Safe, Suspicious or Malicious, "
    "(3) list the URLs, domains or IPs that should be blocked. "
    "Use only facts from the email and the evidence. If the evidence for something is missing or shows an error, "
    "say so in your reasoning and still give your best decision."
)
HUMAN_PROMPT = "Email (raw):\n{email}\n\nVirusTotal evidence (candidate -> stats):\n{evidence}"


class SingleAgent:
    """One LLM call does everything: choose the indicators, judge them and decide what to block."""
    FIELDS = ("urls", "ips", "overall_risk", "block_targets", "reasoning")

    def __init__(self, chain):
        self.chain = chain  # any object with .invoke(dict) -> object or dict with the FIELDS

    @classmethod
    def from_config(cls) -> "SingleAgent":
        from typing import List

        from langchain_core.prompts import ChatPromptTemplate
        from pydantic import BaseModel, Field

        from tools.llm_factory import get_llm

        class SingleAnswer(BaseModel):
            """The complete answer of the single agent."""

            urls: List[str] = Field(default_factory=list, description="every real URL indicator in the email")
            ips: List[str] = Field(default_factory=list, description="every real IP address indicator")
            overall_risk: str = Field(default="Safe", description="Safe, Suspicious or Malicious")
            block_targets: List[str] = Field(default_factory=list, description="URLs, domains or IPs to block")
            reasoning: str = Field(default="", description="One or two sentences")

        prompt = ChatPromptTemplate.from_messages([("system", SYSTEM_PROMPT), ("human", HUMAN_PROMPT)])
        return cls(prompt | get_llm().with_structured_output(SingleAnswer))

    def analyze(self, raw_email: str, evidence: dict) -> dict:
        answer = self.chain.invoke({"email": raw_email[:6000], "evidence": json.dumps(evidence, indent=2)})
        data = answer if isinstance(answer, dict) else {k: getattr(answer, k, None) for k in self.FIELDS}
        return {"urls": list(data.get("urls") or []), "ips": list(data.get("ips") or []),
                "overall_risk": str(data.get("overall_risk") or "").strip().title(),
                "block_targets": list(data.get("block_targets") or []),
                "reasoning": str(data.get("reasoning") or "")}


def _norm(item: str) -> str:
    return item.strip().rstrip(".,;:!?)")


def score_extraction(pred_urls, pred_ips, truth: dict, raw_text: str) -> dict:
    """Compares found indicators with the true ones. 'invented' = reported but not written in the email."""
    t_urls = {_norm(u) for u in truth["urls"]}
    hosts = {urlparse(u).hostname for u in t_urls}  # an IP that is only a URL host is not counted twice
    t_ips = {i for i in truth["ips"] if i not in hosts}
    p_urls = {_norm(u) for u in pred_urls if u}
    p_ips = {_norm(i) for i in pred_ips if i and _norm(i) not in hosts}
    predicted, expected = p_urls | p_ips, t_urls | t_ips
    return {"tp": len(predicted & expected), "fp": len(predicted - expected),
            "fn": len(expected - predicted), "invented": sorted(x for x in predicted if x not in raw_text)}


def build_evidence(vt, raw_candidates: dict) -> dict:
    """VirusTotal answer for every candidate the plain regex found (what both sides may look at)."""
    candidates = [(u["value"], "url") for u in raw_candidates["indicators"]["urls"]]
    candidates += [(ip, "ip") for ip in raw_candidates["indicators"]["ips"]]
    sender = raw_candidates["sender"]["domain"]
    if sender:
        candidates.append((sender, "domain"))
    evidence = {}
    for value, kind in candidates:
        try:
            evidence[value] = vt.scan(value, kind)
        except VTError as err:
            evidence[value] = {"error": err.kind}
    return evidence


class AgentComparison:
    def __init__(self, single_agent, validator=None, workdir=None, truth_path=None,
                 results_path=None, table_path=None):
        truth = json.loads(Path(truth_path or Config.TRUTH_FILE).read_text(encoding="utf-8"))
        truth.pop("_comment", None)
        self.truth = truth
        self.single = single_agent
        self.runner = ScenarioRunner(workdir or Config.BASE_DIR / "outputs" / "compare_run")
        self.raw_extractor = ExtractorAgent()          # plain regex: the candidates both sides may look at
        self.extractor = ExtractorAgent(validator)     # multi-agent extractor (regex + guarded LLM)
        self.vt = VTClient(mock=True)
        self.results_path = Path(results_path or Config.REPORT_DIR / "agent_comparison.json")
        self.table_path = Path(table_path or Config.REPORT_DIR / "agent_comparison.md")

    def run(self) -> dict:
        rows = [self._compare_one(mail) for mail in EmailLoader().load_all(Config.EMAIL_DIR)]
        provider = Config.LLM_PROVIDER
        result = {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                  "llm": f"{provider} / {Config.LLM_MODEL or DEFAULT_MODELS.get(provider, 'default')}",
                  "rows": rows,
                  "summary": {"multi": self._summarize(rows, "multi"), "single": self._summarize(rows, "single")},
                  "caveat": CAVEAT}
        self.results_path.parent.mkdir(parents=True, exist_ok=True)
        self.results_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        self.table_path.write_text("## Single-agent baseline comparison\n\n" + comparison_markdown(result),
                                   encoding="utf-8")
        return result

    # ---------- helpers ----------
    def _compare_one(self, mail) -> dict:
        entry = self.truth.get(mail.email_id)
        if entry is None:
            raise ValueError(f"No label for {mail.email_id} in data/ground_truth.json")
        raw = Path(mail.source_file).read_text(encoding="utf-8", errors="ignore")
        pipe = self.runner.pipeline

        # multi-agent: extractor (+ guard) -> scanner -> planner
        extracted = self.extractor.extract(mail)
        scan = pipe.scanner.scan(extracted)
        outcome = pipe.planner.plan(scan)["outcome"]
        multi = self._side(entry, raw, [u["value"] for u in extracted["indicators"]["urls"]],
                           extracted["indicators"]["ips"], outcome)

        # single agent: one prompt with the email and the same kind of evidence
        evidence = build_evidence(self.vt, self.raw_extractor.extract(mail))
        try:
            answer = self.single.analyze(raw, evidence)
            outcome = {"Malicious": "PENDING_APPROVAL", "Suspicious": "PENDING_APPROVAL",
                       "Safe": "CLOSED_SAFE"}.get(answer["overall_risk"], "ERROR")
            single = self._side(entry, raw, answer["urls"], answer["ips"], outcome)
            single["risk"] = answer["overall_risk"]
        except Exception as exc:  # API limit, bad key, unparsable answer ...
            single = self._side(entry, raw, [], [], "ERROR")
            single["risk"], single["error"] = None, type(exc).__name__
        return {"email_id": mail.email_id, "true_label": entry["label"], "multi": multi, "single": single}

    @staticmethod
    def _side(entry, raw, urls, ips, outcome) -> dict:
        score = score_extraction(urls, ips, entry["indicators"], raw)
        return {"outcome": outcome, "result": AccuracyEvaluator._judge(entry["label"], outcome), **score}

    @staticmethod
    def _summarize(rows: list, side: str) -> dict:
        tp = sum(r[side]["tp"] for r in rows)
        fp = sum(r[side]["fp"] for r in rows)
        fn = sum(r[side]["fn"] for r in rows)
        verdicts = Counter(r[side]["result"] for r in rows)
        return {"extraction_tp": tp, "extraction_fp": fp, "extraction_fn": fn,
                "extraction_precision": round(tp / (tp + fp), 3) if tp + fp else None,
                "extraction_recall": round(tp / (tp + fn), 3) if tp + fn else None,
                "invented_indicators": sum(len(r[side]["invented"]) for r in rows),
                "verdicts": dict(verdicts),
                "threats_missed": verdicts["FN"], "false_alarms": verdicts["FP"],
                "deferred_to_human": verdicts["DEFERRED"], "errors": verdicts["ERROR"]}


def _pct(value) -> str:
    return "n/a" if value is None else f"{value * 100:.0f}%"


def comparison_markdown(result: dict) -> str:
    m, s = result["summary"]["multi"], result["summary"]["single"]
    lines = [f"LLM used by both sides: {result['llm']}", "",
             "| Measure | Multi-agent pipeline | Single agent |", "|---|---|---|",
             f"| Indicator extraction precision | {_pct(m['extraction_precision'])} | {_pct(s['extraction_precision'])} |",
             f"| Indicator extraction recall | {_pct(m['extraction_recall'])} | {_pct(s['extraction_recall'])} |",
             f"| Invented indicators (not in the email) | {m['invented_indicators']} | {s['invented_indicators']} |",
             f"| Threats missed (FN) | {m['threats_missed']} | {s['threats_missed']} |",
             f"| False alarms (FP) | {m['false_alarms']} | {s['false_alarms']} |",
             f"| Left to a human (API failure) | {m['deferred_to_human']} | n/a (no fallback) |",
             f"| Errors | {m['errors']} | {s['errors']} |", "",
             "| Email | True label | Multi-agent | Single agent | Multi tp/fp/fn | Single tp/fp/fn |",
             "|---|---|---|---|---|---|"]
    for r in result["rows"]:
        a, b = r["multi"], r["single"]
        lines.append(f"| {r['email_id']} | {r['true_label']} | {a['result']} | {b['result']} | "
                     f"{a['tp']}/{a['fp']}/{a['fn']} | {b['tp']}/{b['fp']}/{b['fn']} |")
    lines += ["", "TP = threat flagged, TN = clean cleared, FP = false alarm, FN = threat missed, "
                  "DEFERRED = sent to a human.", "", f"Note: {result['caveat']}", ""]
    return "\n".join(lines)


def main() -> None:
    from agents.validator import IndicatorValidator

    result = AgentComparison(SingleAgent.from_config(), IndicatorValidator.from_config()).run()
    print(f"Single agent vs multi-agent pipeline ({result['llm']})\n")
    print(f"{'Email':<22} {'True label':<11} {'Multi':<9} {'Single':<9}")
    for r in result["rows"]:
        print(f"{r['email_id']:<22} {r['true_label']:<11} {r['multi']['result']:<9} {r['single']['result']:<9}")
    m, s = result["summary"]["multi"], result["summary"]["single"]
    print(f"\nInvented indicators: multi {m['invented_indicators']}, single {s['invented_indicators']}")
    print(f"Threats missed:      multi {m['threats_missed']}, single {s['threats_missed']}")
    print(f"False alarms:        multi {m['false_alarms']}, single {s['false_alarms']}")
    print(f"\nFull table: {Config.REPORT_DIR / 'agent_comparison.md'}")


if __name__ == "__main__":
    main()
